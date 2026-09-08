// (4) The Xbyak / trampoline W^X check.
//
// Allocate via Trampoline::AllocTrampoline and Platform::PageAllocNear,
// write code, execute it, then separately simulate a strict noexec/W^X
// policy (mmap PROT_READ|PROT_WRITE, write, mprotect to R|X before
// executing) and document what the fork actually does today.
//
// FINDING (empirically confirmed below, not inferred from reading source
// alone — the naive reading of Platform_Linux.hpp is "permanently RWX",
// which PART A shows is not quite what happens in practice):
//
//   1. Platform::PageAllocNear's mmap call always requests
//      PROT_READ|WRITE|EXEC. Immediately after allocation, before any
//      WriteData call has touched the page, it really is simultaneously
//      writable and executable — a genuine W^X violation at the moment of
//      allocation, unconditionally, for every trampoline page.
//   2. Platform::ProtectWrite (which every WriteData call funnels through
//      — i.e. every RelHook/ASMPatch/CaveHook site write) mprotects the
//      TARGET page to RWX, memcpy's, then drops back to R|X afterward.
//      Because mprotect is page-granular, this restore affects the WHOLE
//      trampoline page, not just the bytes just written — so in practice,
//      once a trampoline page has had its first write, it rests at R-X
//      between writes and is only briefly RWX again during each
//      individual WriteData call's own memcpy.
//   3. Net effect: a trampoline page is PERMANENTLY RWX only in the narrow
//      window between mmap and its first WriteData call (unrealistic in
//      practice — every hook's own construction writes to its trampoline
//      slot immediately), and otherwise sits at R-X with brief RWX pulses
//      during each write. Still not W^X-clean (a strict policy would
//      reject the pulses too, and the *initial* mmap(...|PROT_EXEC)
//      request would fail before any of this even runs), but "briefly
//      W+X during writes, R-X at rest" is a meaningfully smaller attack
//      surface than "permanently RWX for the process lifetime".
//
// A kernel/LSM/container policy that enforces W^X (PaX MPROTECT, an SELinux
// policy denying execmem, a seccomp filter on mprotect(PROT_EXEC) after
// PROT_WRITE, etc.) would make BOTH the initial mmap(...|PROT_EXEC) in
// PageAllocNear AND the mprotect(...|PROT_EXEC) in ProtectWrite fail
// outright — which breaks every hook mechanism this harness exercises,
// since all three (RelHook, ASMPatch, CaveHook) funnel through WriteData.
//
// This container has no such policy (see PART A), and nothing in this
// workspace's documentation records the Steam sniper runtime enforcing one
// either — pressure-vessel is a bind-mount sandbox, not a PaX/SELinux MAC
// policy, and Wine/Proton's own JIT (and countless native-Linux mods that
// predate this port) already depend on RWX or write-then-exec pages working
// under it. So this is a THEORETICAL risk under sniper as best this
// workspace can confirm, not a confirmed failure — but the fork's own code
// is not defensive against it either way. PART B proves the safer
// alternative (mmap RW, write, mprotect RX) works for the exact same byte
// sequences DKUtil generates, so a future hardening pass has a proven
// fallback path if this ever needs to change to satisfy a stricter policy.

#include "check.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>

namespace
{
	using RetInt = int (*)();

	// A tiny `mov eax, 0x2A; ret` (returns 42) — the same class of raw
	// byte sequence DKUtil's own trampolines are made of (see JmpRel /
	// CallRip / SubRsp in JIT.hpp), so this is a fair proxy for "does the
	// fork's generated code run under a write-then-exec discipline".
	constexpr unsigned char kReturn42[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

	// Parse /proc/self/maps for the permission bits of the page containing
	// a_addr. Returns e.g. "rwxp", or "" if not found.
	std::string permsOf(std::uintptr_t a_addr)
	{
		std::ifstream in("/proc/self/maps");
		std::string   line;
		while (std::getline(in, line)) {
			std::uintptr_t lo, hi;
			char           perms[8]{};
			if (std::sscanf(line.c_str(), "%lx-%lx %7s", &lo, &hi, perms) == 3) {
				if (a_addr >= lo && a_addr < hi) {
					return perms;
				}
			}
		}
		return {};
	}
}  // namespace

int main()
{
	// ---- PART A: the fork's actual code path -------------------------
	DKUtil::Hook::Trampoline::AllocTrampoline(1 << 8);
	auto* tramMem = DKUtil::Hook::Trampoline::Allocate(sizeof(kReturn42));
	CHECK(tramMem != nullptr);

	// Empirical check, not inference: what did Platform::PageAllocNear
	// actually hand back, BEFORE any WriteData call has touched the page?
	// (Trampoline::Allocate only bumps the singleton's bump-allocator
	// pointer within the already-mmap'd region — it does not itself
	// mprotect anything.)
	auto tramPermsBeforeWrite = permsOf(reinterpret_cast<std::uintptr_t>(tramMem));
	std::fprintf(stderr, "[info] trampoline page perms right after PageAllocNear (no write yet): %s\n", tramPermsBeforeWrite.c_str());
	CHECK(tramPermsBeforeWrite == "rwxp");  // W^X FINDING #1: the raw near-alloc is unconditionally RWX

	// DKUtil::Hook::WriteData is the function every hook installer in this
	// harness (RelHook/ASMPatch/CaveHook) funnels through. It mprotects the
	// destination to RWX, memcpy's, then drops back down to R|X — so by the
	// time this call returns, the transient RWX window has already closed.
	DKUtil::Hook::WriteData(reinterpret_cast<std::uintptr_t>(tramMem), kReturn42, sizeof(kReturn42), false);

	auto tramPermsAfterWrite = permsOf(reinterpret_cast<std::uintptr_t>(tramMem));
	std::fprintf(stderr, "[info] trampoline page perms after WriteData (ProtectWrite restores R-X): %s\n", tramPermsAfterWrite.c_str());
	CHECK(tramPermsAfterWrite == "r-xp");  // W^X FINDING #2: ProtectWrite always restores R-X afterward (mprotect is page-granular, so this flips the WHOLE page back, not just the bytes just written)

	auto fn = reinterpret_cast<RetInt>(tramMem);
	CHECK_EQ(fn(), 42);  // the page executes correctly in its resting R-X state

	// ---- PART B: does the SAME byte sequence work under a strict
	// write-then-exec discipline the fork does NOT currently use? --------
	// This package owns test-linux/, not DKUtil/include — so this is a
	// standalone allocator mirroring what PageAllocNear/ProtectWrite
	// *could* do, not a change to the fork itself.
	{
		const std::size_t len = 4096;
		void*              mem = ::mmap(nullptr, len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		CHECK(mem != MAP_FAILED);

		std::memcpy(mem, kReturn42, sizeof(kReturn42));

		int rc = ::mprotect(mem, len, PROT_READ | PROT_EXEC);
		CHECK_EQ(rc, 0);

		auto strictPerms = permsOf(reinterpret_cast<std::uintptr_t>(mem));
		std::fprintf(stderr, "[info] write-then-exec page perms: %s\n", strictPerms.c_str());
		CHECK(strictPerms == "r-xp");  // never simultaneously W and X

		auto strictFn = reinterpret_cast<RetInt>(mem);
		CHECK_EQ(strictFn(), 42);  // proves DKUtil's byte sequences don't NEED RWX to run

		::munmap(mem, len);
	}

	// ---- PART C: methodology sanity check — a genuinely non-executable
	// page really does fault on execution (so PART A/B's passes are
	// meaningful, not a no-op). Run in a child process: attempting to
	// execute a noexec page is expected to crash it. --------------------
	{
		pid_t pid = ::fork();
		CHECK(pid >= 0);
		if (pid == 0) {
			const std::size_t len = 4096;
			void*              mem = ::mmap(nullptr, len, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (mem == MAP_FAILED) {
				_exit(2);
			}
			std::memcpy(mem, kReturn42, sizeof(kReturn42));
			// deliberately do NOT mprotect PROT_EXEC
			auto noexecFn = reinterpret_cast<RetInt>(mem);
			int  result = noexecFn();  // must fault before returning
			(void)result;
			_exit(3);  // reached only if the CPU/kernel did NOT enforce NX
		}
		int status = 0;
		::waitpid(pid, &status, 0);
		bool crashed = WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
		std::fprintf(stderr, "[info] noexec-page execution child status: %s%d\n",
			WIFSIGNALED(status) ? "signal " : "exit ", WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status));
		CHECK(crashed);
	}

	REPORT_AND_RETURN();
}
