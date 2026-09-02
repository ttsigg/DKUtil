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

#if !defined(_WIN32)

#	include <cstdint>
#	include <cstdio>
#	include <cstdlib>
#	include <fstream>
#	include <string>
#	include <string_view>
#	include <unordered_map>
#	include <unordered_set>

#	include <nlohmann/json.hpp>

#	include "DKUtil/Impl/Hook/Platform_Linux.hpp"

namespace DKUtil::Hook
{
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
			return Platform::ModuleBase(0) + s->va;
		}

		// Deliberate accessor for the non-equivalent cases (inlined bodies). Returns
		// the absolute host address and, via a_guestEntry, where the folded body
		// starts. Callers must install a cave/ASM patch, never a call rewrite.
		[[nodiscard]] std::uintptr_t resolve_host(std::string_view a_key,
			std::uintptr_t* a_guestEntry = nullptr) const noexcept
		{
			const Site* s = lookup(a_key);
			if (!s || s->va == 0) {
				return 0;
			}
			const auto base = Platform::ModuleBase(0);
			if (a_guestEntry) {
				*a_guestEntry = s->guest_entry ? base + s->guest_entry : 0;
			}
			return base + s->va;
		}

	private:
		SiteCatalog() { load(); }

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

			_buildId = j.value("build_id", std::string{});
			const auto sites = j.find("sites");
			if (sites == j.end() || !sites->is_object()) {
				std::fprintf(stderr, "[DKUtil] site catalog has no 'sites' object\n");
				return;
			}

			for (auto it = sites->begin(); it != sites->end(); ++it) {
				const auto& v = it.value();
				Site        s;
				s.kind = parse_kind(v.value("kind", std::string{ "unknown" }));
				s.relation = parse_relation(v.value("relation", std::string{ "unknown" }));
				s.va = parse_addr(v.value("va", std::string{}));
				s.guest_entry = parse_addr(v.value("guest_entry", std::string{}));
				s.len = v.value("len", std::size_t{ 0 });
				s.index = v.value("index", -1);
				s.tier = v.value("tier", std::string{});
				s.hook_mechanism = v.value("hook_mechanism", std::string{});
				s.signature = v.value("signature", std::string{});
				_sites.emplace(it.key(), std::move(s));
			}

			_loaded = true;
			std::fprintf(stderr, "[DKUtil] site catalog loaded: build '%s', %zu sites\n",
				_buildId.c_str(), _sites.size());
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

		bool                                     _loaded{ false };
		std::string                              _buildId;
		std::unordered_map<std::string, Site>    _sites;
		mutable std::unordered_set<std::string>  _warned;
	};
}  // namespace DKUtil::Hook

#endif  // !_WIN32
