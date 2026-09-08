#pragma once

// Site catalog — the Linux replacement for compile-time byte-pattern scanning.
//
// On Windows, DKUtil resolves a hook target by scanning bg3.exe's .text for a
// byte pattern. Those MSVC patterns cannot match the clang/LLD Linux .text, so
// on Linux search_pattern<"..."> instead looks the pattern string up in a
// build-keyed catalog produced by the reverse-engineering pipeline
// (docs/linux-port/tools/gen_site_catalog.py). See DKUTIL-PORT-DESIGN.md §4.
//
// A miss returns nullptr (not FATAL): the mods already skip a hook whose target
// did not resolve, so a partially-populated catalog still boots the game with
// the resolved hooks live.
//
// TWO SAFETY GATES, because every `va` in here is an absolute address valid for
// exactly one game build:
//
//  1. BUILD IDENTITY. A catalog generated for build N against a game patched to
//     N+1 does not fail loudly — it resolves cleanly and hands back whatever
//     object now lives at that address, which the mods then write to. The only
//     identity a Linux ELF actually carries is its GNU build-id note, so the
//     catalog may declare `"linux_build_id": "<hex>"` (and/or `"linux_text_size"`)
//     at top level; when it does, a mismatch against the running program is
//     refused outright — nothing resolves. The Windows-side `build_id`
//     ("4.1.1.7398") is a PE VERSIONINFO string with no ELF counterpart, so it
//     cannot be checked here; it stays informational.
//     ⚠ A catalog that declares NO Linux identity cannot be verified. That is
//     logged once, loudly, and gate 2 becomes the only protection.
//     `gen_site_catalog.py::linux_identity()` emits BOTH fields (build-id from
//     the bg3 ELF's NT_GNU_BUILD_ID note; text size from the largest PF_X
//     PT_LOAD's p_memsz, which is exactly what Platform::ModuleText reports),
//     so on a GENERATED catalog this gate is live. Only a hand-written one, or
//     one generated on a machine with no Linux/bg3 present, takes the
//     unverifiable path.
//
//  2. BOUNDS. Every resolved address is range-checked against the running
//     program's own mapped image, and code kinds additionally against its
//     executable segment. A stale or corrupt row therefore returns 0 (the
//     designed WARN-and-skip path) instead of a pointer, which is what makes it
//     safe for a consumer to so much as read the byte at a returned CALL_SITE.

#if !defined(_WIN32)

#	include <cstdint>
#	include <cstdio>
#	include <cstdlib>
#	include <cstring>
#	include <fstream>

#	include <elf.h>
#	include <link.h>
#	include <string>
#	include <string_view>
#	include <unordered_map>
#	include <unordered_set>

#	include <nlohmann/json.hpp>

#	include "DKUtil/Impl/Hook/Platform_Linux.hpp"

namespace DKUtil::Hook
{
	namespace detail
	{
		struct ImageRange
		{
			std::uintptr_t begin{ 0 };
			std::size_t    size{ 0 };
		};

		struct ImageProbe
		{
			std::uintptr_t lo{ 0 };
			std::uintptr_t hi{ 0 };
			std::string    buildId;
			bool           found{ false };
		};

		inline std::string HexOf(const unsigned char* a_bytes, std::size_t a_n) noexcept
		{
			static constexpr char kHex[] = "0123456789abcdef";
			std::string           out;
			out.reserve(a_n * 2);
			for (std::size_t i = 0; i < a_n; ++i) {
				out.push_back(kHex[a_bytes[i] >> 4]);
				out.push_back(kHex[a_bytes[i] & 0xF]);
			}
			return out;
		}

		// Main program only (dlpi_name is the empty string): span every PT_LOAD to
		// get the mapped image range, and read NT_GNU_BUILD_ID out of PT_NOTE.
		inline int image_cb(struct ::dl_phdr_info* a_info, std::size_t, void* a_data) noexcept
		{
			auto* probe = static_cast<ImageProbe*>(a_data);
			if (a_info->dlpi_name != nullptr && a_info->dlpi_name[0] != '\0') {
				return 0;  // not the main program; keep looking
			}

			bool any = false;
			for (int i = 0; i < a_info->dlpi_phnum; ++i) {
				const auto& ph = a_info->dlpi_phdr[i];
				if (ph.p_type == PT_LOAD) {
					const auto lo = static_cast<std::uintptr_t>(a_info->dlpi_addr + ph.p_vaddr);
					const auto hi = lo + static_cast<std::uintptr_t>(ph.p_memsz);
					if (!any || lo < probe->lo) {
						probe->lo = lo;
					}
					if (!any || hi > probe->hi) {
						probe->hi = hi;
					}
					any = true;
				} else if (ph.p_type == PT_NOTE && probe->buildId.empty()) {
					const auto* cur = reinterpret_cast<const unsigned char*>(a_info->dlpi_addr + ph.p_vaddr);
					const auto* end = cur + ph.p_memsz;
					while (cur + sizeof(::ElfW(Nhdr)) <= end) {
						::ElfW(Nhdr) nhdr{};
						std::memcpy(&nhdr, cur, sizeof(nhdr));
						const auto* name = cur + sizeof(nhdr);
						const auto  nameSz = (nhdr.n_namesz + 3u) & ~3u;
						const auto* desc = name + nameSz;
						const auto  descSz = (nhdr.n_descsz + 3u) & ~3u;
						if (desc + nhdr.n_descsz > end) {
							break;
						}
						if (nhdr.n_type == NT_GNU_BUILD_ID && nhdr.n_namesz == 4 &&
							std::memcmp(name, "GNU\0", 4) == 0 && nhdr.n_descsz > 0) {
							probe->buildId = HexOf(desc, nhdr.n_descsz);
							break;
						}
						cur = desc + descSz;
					}
				}
			}

			probe->found = any;
			return 1;  // stop iteration
		}

		[[nodiscard]] inline const ImageProbe& Probe() noexcept
		{
			static const ImageProbe probe = [] {
				ImageProbe p{};
				::dl_iterate_phdr(&image_cb, &p);
				return p;
			}();
			return probe;
		}

		[[nodiscard]] inline const ImageRange& ImageBounds() noexcept
		{
			static const ImageRange range = [] {
				const auto& p = Probe();
				return p.found && p.hi > p.lo ? ImageRange{ p.lo, static_cast<std::size_t>(p.hi - p.lo) } :
				                                ImageRange{};
			}();
			return range;
		}

		[[nodiscard]] inline std::string RunningBuildId() noexcept { return Probe().buildId; }
	}  // namespace detail

	class SiteCatalog
	{
	public:
		enum class Kind
		{
			CallSite,    // a direct-call E8 site; write_call rewrites its operand
			FuncEntry,   // a function entry
			Global,      // a resolved data address (rip-decode already done at RE time)
			PatchSite,   // an in-function patch point; `len` = clang byte length to overwrite
			VtableSlot,  // a vtable base; `index` = Itanium-verified slot
			Unknown,
		};

		// How the Linux address relates to the Windows function the pattern names.
		// This is NOT decoration: for an inlined target the recorded address is the
		// HOST function that absorbed the body, which is a DIFFERENT function. Handing
		// that to write_call would rewrite the wrong call site. Measured 2026-09-01:
		// 3 of 5 adversarially-confirmed pilot results are Inlined, so a flat address
		// field is unsafe by default. See DKUTIL-PORT-DESIGN.md §14.
		enum class Relation
		{
			Equivalent,   // true function<->function counterpart; safe to hook directly
			InlinedInto,  // body folded into `va` (the host). NOT a counterpart address.
			Unknown,      // unclassified — treated as unsafe
		};

		struct Site
		{
			Kind           kind{ Kind::Unknown };
			Relation       relation{ Relation::Unknown };
			std::uintptr_t va{ 0 };           // address in the bg3 ELF's own (unbiased) vaddr space
			std::uintptr_t guest_entry{ 0 };  // InlinedInto: where the folded body begins inside the host
			// InlinedInto, OPTIONAL: the matching exit/join point inside the host, for a
			// target whose Windows counterpart was a WRAP (do X, call original, undo X) and
			// therefore needs two hook points rather than one. 0 when the catalog row does
			// not declare one -- which is the norm; only rows that were adversarially
			// reviewed for a second window carry it. Read from the row's "guest_exit".
			std::uintptr_t guest_exit{ 0 };
			std::size_t    len{ 0 };          // PatchSite: bytes to overwrite
			int            index{ -1 };       // VtableSlot: slot index
			std::string    tier;              // provenance tier (verified-by-disassembly, ...)
			std::string    hook_mechanism;    // write_call | cave | vtable_slot | none
			std::string    signature;         // Linux prototype when it differs (DAE, arg promotion, sret)
		};

		[[nodiscard]] static SiteCatalog& get() noexcept
		{
			static SiteCatalog instance;
			return instance;
		}

		[[nodiscard]] bool               loaded() const noexcept { return _loaded; }
		[[nodiscard]] const std::string& build_id() const noexcept { return _buildId; }

		// The Linux identity the catalog declared (empty when it declared none)
		// and the running program's own GNU build-id.
		[[nodiscard]] const std::string& linux_build_id() const noexcept { return _linuxBuildId; }
		[[nodiscard]] static const std::string& running_build_id() noexcept
		{
			static const std::string id = detail::RunningBuildId();
			return id;
		}
		// True only when the catalog declared a Linux identity AND it matched.
		[[nodiscard]] bool identity_verified() const noexcept { return _identityVerified; }

		// ---- bounds (gate 2) -------------------------------------------------
		// Range of the running program's whole mapped image / its executable
		// segment, both absolute. Computed once from the program headers.
		[[nodiscard]] static bool module_image_contains(std::uintptr_t a_addr) noexcept
		{
			const auto& b = detail::ImageBounds();
			return b.size != 0 && a_addr >= b.begin && a_addr < b.begin + b.size;
		}

		[[nodiscard]] static bool module_text_contains(std::uintptr_t a_addr) noexcept
		{
			static const auto text = Platform::ModuleText(0);
			return text.textxSize != 0 && a_addr >= text.textx && a_addr < text.textx + text.textxSize;
		}

		// The Site descriptor for a pattern key, or nullptr if absent.
		[[nodiscard]] const Site* lookup(std::string_view a_key) const noexcept
		{
			auto it = _sites.find(std::string{ a_key });
			return it == _sites.end() ? nullptr : &it->second;
		}

		// Absolute runtime address for a pattern key (module load bias + site vaddr),
		// or 0 if the key is absent / unresolved / not safely hookable.
		//
		// SAFETY: only a Relation::Equivalent site resolves. An InlinedInto site's
		// address is the HOST function, not the target's counterpart — returning it
		// here would make write_call rewrite a different function's call site, which
		// is silent memory corruption, not a visible failure. Inlined targets need a
		// cave/ASM patch at guest_entry and must be fetched deliberately via lookup().
		[[nodiscard]] std::uintptr_t resolve(std::string_view a_key) const noexcept
		{
			const Site* s = lookup(a_key);
			if (!s || s->va == 0) {
				warn_miss(a_key);
				return 0;
			}
			if (s->relation != Relation::Equivalent) {
				warn_unsafe(a_key);
				return 0;
			}
			return checked(a_key, *s, Platform::ModuleBase(0) + s->va);
		}

		// Deliberate accessor for the non-equivalent cases (inlined bodies). Returns
		// the absolute host address and, via a_guestEntry, where the folded body
		// starts. Callers must install a cave/ASM patch, never a call rewrite.
		// `a_guestExit` is optional and stays 0 for the (usual) row that declares no
		// second window; it is bounds-checked exactly like a_guestEntry.
		[[nodiscard]] std::uintptr_t resolve_host(std::string_view a_key,
			std::uintptr_t* a_guestEntry = nullptr,
			std::uintptr_t* a_guestExit = nullptr) const noexcept
		{
			const Site* s = lookup(a_key);
			if (!s || s->va == 0) {
				return 0;
			}
			const auto base = Platform::ModuleBase(0);
			const auto host = checked(a_key, *s, base + s->va);
			if (a_guestEntry) {
				*a_guestEntry = 0;
			}
			if (a_guestExit) {
				*a_guestExit = 0;
			}
			if (!host) {
				return 0;
			}
			if (a_guestEntry && s->guest_entry) {
				// A guest entry that fails the bounds check is not fatal to the host
				// address, but the caller must not patch there: report 0 for it.
				const auto guest = base + s->guest_entry;
				*a_guestEntry = module_text_contains(guest) ? guest : 0;
				if (!*a_guestEntry) {
					warn_out_of_bounds(a_key, guest, "guest_entry outside the executable segment");
				}
			}
			if (a_guestExit && s->guest_exit) {
				const auto guest = base + s->guest_exit;
				*a_guestExit = module_text_contains(guest) ? guest : 0;
				if (!*a_guestExit) {
					warn_out_of_bounds(a_key, guest, "guest_exit outside the executable segment");
				}
			}
			return host;
		}

	private:
		SiteCatalog() { load(); }

		// Gate 2. `a_abs` is the absolute address a row resolves to; returns it
		// only when it lies inside the running program, else 0 + one WARN.
		[[nodiscard]] std::uintptr_t checked(std::string_view a_key, const Site& a_site,
			std::uintptr_t a_abs) const noexcept
		{
			if (!module_image_contains(a_abs)) {
				warn_out_of_bounds(a_key, a_abs, "outside the running program's mapped image");
				return 0;
			}
			// Anything a consumer will execute, read as code, or splice into must be
			// in the executable segment. Globals (.bss/.data) and vtable slots
			// (.data.rel.ro) legitimately are not.
			const bool isCode = a_site.kind == Kind::CallSite || a_site.kind == Kind::FuncEntry ||
			                    a_site.kind == Kind::PatchSite;
			if (isCode && !module_text_contains(a_abs)) {
				warn_out_of_bounds(a_key, a_abs, "code site outside the executable segment");
				return 0;
			}
			return a_abs;
		}

		void load() noexcept
		{
			std::string path;
			if (const char* env = std::getenv("DKU_SITE_CATALOG")) {
				path = env;
			} else {
				path = "NativeMods/site-catalog.json";  // relative to game cwd (bin/)
			}

			std::ifstream in(path);
			if (!in) {
				std::fprintf(stderr,
					"[DKUtil] site catalog not found at '%s' — no game-function hooks will resolve. "
					"Set DKU_SITE_CATALOG or place site-catalog.json in NativeMods/.\n",
					path.c_str());
				return;
			}

			nlohmann::json j;
			try {
				in >> j;
			} catch (const std::exception& e) {
				std::fprintf(stderr, "[DKUtil] site catalog parse error: %s\n", e.what());
				return;
			}

			// EVERY read below can throw. nlohmann `value()` raises type_error.302 when
			// the key is PRESENT but holds another type -- a JSON `null` included, and
			// the shipping catalog already carries nulls (win_callee/win_site/win_fn on
			// unresolved rows). load() is noexcept, so an escaping throw is
			// std::terminate: the game dies at plugin load instead of taking the
			// designed WARN-and-skip path. So: the header reads go in one try, and each
			// row in its own, making one malformed row cost that row alone.
			try {
				_buildId = j.value("build_id", std::string{});
				_linuxBuildId = j.value("linux_build_id", std::string{});
			} catch (const std::exception& e) {
				std::fprintf(stderr,
					"[DKUtil] site catalog header is malformed (%s) — refusing the catalog.\n", e.what());
				_buildId.clear();
				_linuxBuildId.clear();
				return;
			}

			std::size_t declaredTextSize = 0;
			try {
				declaredTextSize = j.value("linux_text_size", std::size_t{ 0 });
			} catch (const std::exception& e) {
				// Refuse rather than continue: a malformed identity field must never
				// downgrade silently into "no identity declared".
				std::fprintf(stderr,
					"[DKUtil] site catalog 'linux_text_size' is malformed (%s) — refusing the catalog.\n",
					e.what());
				return;
			}

			// --- gate 1: build identity ---------------------------------------
			if (!verify_identity(declaredTextSize)) {
				// Deliberately leave _loaded false and _sites empty: with the wrong
				// build every absolute address in the file is a different object.
				return;
			}

			const auto sites = j.find("sites");
			if (sites == j.end() || !sites->is_object()) {
				std::fprintf(stderr, "[DKUtil] site catalog has no 'sites' object\n");
				return;
			}

			for (auto it = sites->begin(); it != sites->end(); ++it) {
				try {
					const auto& v = it.value();
					if (!v.is_object()) {
						std::fprintf(stderr,
							"[DKUtil] site catalog row '%s' is not an object — hook skipped.\n",
							it.key().c_str());
						continue;
					}
					Site s;
					s.kind = parse_kind(v.value("kind", std::string{ "unknown" }));
					s.relation = parse_relation(v.value("relation", std::string{ "unknown" }));
					s.va = parse_addr(v.value("va", std::string{}));
					s.guest_entry = parse_addr(v.value("guest_entry", std::string{}));
					s.guest_exit = parse_addr(v.value("guest_exit", std::string{}));
					s.len = v.value("len", std::size_t{ 0 });
					s.index = v.value("index", -1);
					s.tier = v.value("tier", std::string{});
					s.hook_mechanism = v.value("hook_mechanism", std::string{});
					s.signature = v.value("signature", std::string{});
					_sites.emplace(it.key(), std::move(s));
				} catch (const std::exception& e) {
					// WARN-and-skip: a row that cannot be read is simply not installed,
					// exactly as if it carried no `va`.
					std::fprintf(stderr,
						"[DKUtil] site catalog row '%s' is malformed (%s) — hook skipped.\n",
						it.key().c_str(), e.what());
				}
			}

			_loaded = true;
			std::fprintf(stderr, "[DKUtil] site catalog loaded: build '%s', %zu sites (linux identity: %s)\n",
				_buildId.c_str(), _sites.size(),
				_identityVerified ? "verified" : "NOT DECLARED — unverifiable");
		}

		// Returns false when the catalog positively describes a different build.
		[[nodiscard]] bool verify_identity(std::size_t a_declaredTextSize) noexcept
		{
			const auto& running = running_build_id();
			bool        declared = false;

			if (!_linuxBuildId.empty()) {
				declared = true;
				if (running.empty()) {
					std::fprintf(stderr,
						"[DKUtil] site catalog declares linux_build_id '%s' but the running program has no "
						"GNU build-id note — refusing the catalog rather than resolving addresses blind.\n",
						_linuxBuildId.c_str());
					return false;
				}
				if (running != _linuxBuildId) {
					std::fprintf(stderr,
						"[DKUtil] site catalog BUILD MISMATCH — catalog linux_build_id '%s', running program "
						"'%s'. Every address in this catalog belongs to a different build; refusing all %s "
						"sites. Regenerate it (docs/linux-port/tools/gen_site_catalog.py) against this game "
						"build.\n",
						_linuxBuildId.c_str(), running.c_str(), _buildId.c_str());
					return false;
				}
			}

			if (a_declaredTextSize != 0) {
				declared = true;
				const auto text = Platform::ModuleText(0);
				if (text.textxSize != a_declaredTextSize) {
					std::fprintf(stderr,
						"[DKUtil] site catalog BUILD MISMATCH — catalog linux_text_size %zu, running program "
						"%zu. Refusing the catalog.\n",
						a_declaredTextSize, text.textxSize);
					return false;
				}
			}

			if (!declared) {
				std::fprintf(stderr,
					"[DKUtil] WARNING: site catalog (build '%s') declares no Linux build identity, so it "
					"CANNOT be checked against the running program '%s'. If the game has been patched since "
					"the catalog was generated, its addresses now point at different objects. Add "
					"\"linux_build_id\" to the catalog to make this check effective; only range checking "
					"protects you until then.\n",
					_buildId.c_str(), running.empty() ? "(no build-id note)" : running.c_str());
			}

			_identityVerified = declared;
			return true;
		}

		static Kind parse_kind(std::string_view a_k) noexcept
		{
			if (a_k == "call_site") return Kind::CallSite;
			if (a_k == "func_entry") return Kind::FuncEntry;
			if (a_k == "global") return Kind::Global;
			if (a_k == "patch_site") return Kind::PatchSite;
			if (a_k == "vtable_slot") return Kind::VtableSlot;
			return Kind::Unknown;
		}

		static Relation parse_relation(std::string_view a_r) noexcept
		{
			if (a_r == "equivalent") return Relation::Equivalent;
			if (a_r == "inlined_into") return Relation::InlinedInto;
			return Relation::Unknown;
		}

		static std::uintptr_t parse_addr(const std::string& a_s) noexcept
		{
			if (a_s.empty()) return 0;
			return static_cast<std::uintptr_t>(std::strtoull(a_s.c_str(), nullptr, 0));
		}

		void warn_miss(std::string_view a_key) const noexcept
		{
			if (_warned.insert(std::string{ a_key }).second) {
				std::fprintf(stderr, "[DKUtil] unresolved site (hook skipped): %.*s\n",
					static_cast<int>(a_key.size()), a_key.data());
			}
		}

		void warn_unsafe(std::string_view a_key) const noexcept
		{
			if (_warned.insert("unsafe:" + std::string{ a_key }).second) {
				std::fprintf(stderr,
					"[DKUtil] site is not a direct counterpart (inlined/unknown) — refusing to "
					"hand it to a call rewrite; needs a cave patch. Hook skipped: %.*s\n",
					static_cast<int>(a_key.size()), a_key.data());
			}
		}

		void warn_out_of_bounds(std::string_view a_key, std::uintptr_t a_addr, const char* a_why) const noexcept
		{
			if (_warned.insert("oob:" + std::string{ a_key }).second) {
				std::fprintf(stderr,
					"[DKUtil] site resolves to %p, %s — the row is stale or belongs to another build. "
					"Hook skipped: %.*s\n",
					reinterpret_cast<const void*>(a_addr), a_why,
					static_cast<int>(a_key.size()), a_key.data());
			}
		}

		bool                                     _loaded{ false };
		bool                                     _identityVerified{ false };
		std::string                              _linuxBuildId;
		std::string                              _buildId;
		std::unordered_map<std::string, Site>    _sites;
		mutable std::unordered_set<std::string>  _warned;
	};
}  // namespace DKUtil::Hook

#endif  // !_WIN32
