#pragma once

// DKUtil Linux platform seam.
//
// The DKUtil hook layer is written against a tiny set of Windows primitives:
// module .text discovery, near-range executable allocation, and
// protect-then-write. On the native-Linux BG3 build those map cleanly to
// dl_iterate_phdr / mmap / mprotect. This header keeps every syscall in one
// place; Shared.hpp / Trampoline.hpp call into DKUtil::Hook::Platform under
// `#if !defined(_WIN32)` and are otherwise unchanged.
//
// Scope: x86-64 only (so is the target; clang-18/LLD). No thread suspension —
// same startup-window assumption the whole substrate already relies on.

#if !defined(_WIN32)

#	include <cstdint>
#	include <cstring>
#	include <string>
#	include <vector>

#	include <dlfcn.h>
#	include <link.h>
#	include <sys/mman.h>
#	include <unistd.h>

namespace DKUtil::Hook::Platform
{
	// ---- module discovery (replaces the PE Module class' base()/section(textx)) ----

	struct TextRange
	{
		std::uintptr_t base{ 0 };   // load bias (dlpi_addr) of the main object
		std::uintptr_t textx{ 0 };  // start of the executable segment
		std::size_t    textxSize{ 0 };
	};

	namespace detail
	{
		struct PhdrProbe
		{
			bool           wantMain;
			std::uintptr_t wantBase;
			TextRange      out;
			bool           found;
		};

		inline int phdr_cb(struct ::dl_phdr_info* a_info, std::size_t, void* a_data) noexcept
		{
			auto* probe = static_cast<PhdrProbe*>(a_data);

			// Main program: dlpi_name is the empty string. Otherwise match by
			// the load bias the caller asked for.
			const bool isMain = (a_info->dlpi_name == nullptr || a_info->dlpi_name[0] == '\0');
			if (probe->wantMain) {
				if (!isMain) {
					return 0;
				}
			} else if (a_info->dlpi_addr != probe->wantBase) {
				return 0;
			}

			// Pick the executable PT_LOAD segment as .text (largest PF_X, to skip
			// tiny PLT-only exec segments if any).
			std::uintptr_t bestAddr = 0;
			std::size_t    bestSize = 0;
			for (int i = 0; i < a_info->dlpi_phnum; ++i) {
				const auto& ph = a_info->dlpi_phdr[i];
				if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
					if (ph.p_memsz > bestSize) {
						bestSize = ph.p_memsz;
						bestAddr = a_info->dlpi_addr + ph.p_vaddr;
					}
				}
			}

			probe->out.base = a_info->dlpi_addr;
			probe->out.textx = bestAddr;
			probe->out.textxSize = bestSize;
			probe->found = (bestAddr != 0);
			return 1;  // stop iteration
		}
	}  // namespace detail

	// Resolve the executable text range of the main program (a_base == 0) or of
	// the object with the given load bias.
	[[nodiscard]] inline TextRange ModuleText(std::uintptr_t a_base = 0) noexcept
	{
		detail::PhdrProbe probe{ a_base == 0, a_base, {}, false };
		::dl_iterate_phdr(&detail::phdr_cb, &probe);
		return probe.out;
	}

	[[nodiscard]] inline std::uintptr_t ModuleBase(std::uintptr_t a_base = 0) noexcept
	{
		return ModuleText(a_base).base;
	}

	// ---- process/module path (replaces psapi GetModuleName/Path) ----

	[[nodiscard]] inline std::string ExePath() noexcept
	{
		char buf[4096];
		const auto n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
		if (n <= 0) {
			return {};
		}
		return std::string(buf, static_cast<std::size_t>(n));
	}

	[[nodiscard]] inline std::string ExeName() noexcept
	{
		std::string path = ExePath();
		const auto  slash = path.find_last_of('/');
		return slash == std::string::npos ? path : path.substr(slash + 1);
	}

	// Path of the shared object containing a_addr (for a plugin's own path).
	[[nodiscard]] inline std::string ModulePathOf(const void* a_addr) noexcept
	{
		::Dl_info info{};
		if (::dladdr(a_addr, &info) && info.dli_fname) {
			return std::string(info.dli_fname);
		}
		return {};
	}

	// ---- protect-then-write (replaces VirtualProtect + memcpy) ----

	inline constexpr std::size_t kPageSize = 0x1000;

	// Make [dst, dst+size) writable+executable, copy in a_size bytes, then drop
	// back to R|X. The prior protection cannot be queried on POSIX; .text was
	// R|X, which is what we restore. Returns true on success.
	inline bool ProtectWrite(void* a_dst, const void* a_data, std::size_t a_size) noexcept
	{
		const auto addr = reinterpret_cast<std::uintptr_t>(a_dst);
		const auto pageStart = addr & ~(kPageSize - 1);
		const auto pageEnd = (addr + a_size + kPageSize - 1) & ~(kPageSize - 1);
		const auto len = static_cast<std::size_t>(pageEnd - pageStart);
		auto*      page = reinterpret_cast<void*>(pageStart);

		if (::mprotect(page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
			return false;
		}
		std::memcpy(a_dst, a_data, a_size);
		// Best-effort restore; failure here does not corrupt the write.
		::mprotect(page, len, PROT_READ | PROT_EXEC);
		return true;
	}

	// ---- near-range executable allocation (replaces VirtualAlloc near ±2GB) ----

	// Allocate a_size executable bytes within ±2GB of a_from (so 5/6-byte rel32
	// detours can reach it). Walks outward in strides, hinting mmap; verifies the
	// kernel honoured the hint within INT32 range, else releases and retries.
	[[nodiscard]] inline void* PageAllocNear(std::size_t a_size, std::uintptr_t a_from) noexcept
	{
		constexpr std::uintptr_t kRange = static_cast<std::uintptr_t>(1) << 31;  // 2GB
		constexpr std::uintptr_t kStride = static_cast<std::uintptr_t>(1) << 20;  // 1MB
		const std::size_t        len = (a_size + kPageSize - 1) & ~(kPageSize - 1);

		auto tryAt = [&](std::uintptr_t hint) -> void* {
			void* p = ::mmap(reinterpret_cast<void*>(hint), len,
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (p == MAP_FAILED) {
				return nullptr;
			}
			const auto got = reinterpret_cast<std::uintptr_t>(p);
			const std::ptrdiff_t disp = static_cast<std::ptrdiff_t>(got) - static_cast<std::ptrdiff_t>(a_from);
			if (disp >= INT32_MIN && disp <= INT32_MAX) {
				return p;
			}
			::munmap(p, len);
			return nullptr;
		};

		// Probe alternately below and above a_from.
		for (std::uintptr_t off = kStride; off < kRange; off += kStride) {
			if (a_from > off) {
				if (auto* p = tryAt((a_from - off) & ~(kPageSize - 1))) {
					return p;
				}
			}
			if (auto* p = tryAt((a_from + off) & ~(kPageSize - 1))) {
				return p;
			}
		}
		return nullptr;
	}
}  // namespace DKUtil::Hook::Platform

#endif  // !_WIN32
