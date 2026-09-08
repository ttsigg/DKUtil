// (5) SiteCatalog round-trip (resolve vs resolve_host) against a synthetic
// catalog.
//
// Writes a small synthetic site-catalog.json, points DKU_SITE_CATALOG at
// it, and exercises SiteCatalog::get() the way the fork's search_pattern<S>
// would on Linux (see SiteCatalog.hpp). Proves two safety properties:
//
//   * DKUTIL-PORT-DESIGN.md §15 (the inlining finding): resolve() hands back
//     an address ONLY for Relation::Equivalent; an InlinedInto or Unknown site
//     refuses (returns 0) and must go through the deliberate resolve_host()
//     accessor instead, which also reports guest_entry.
//
//   * The bounds gate: a row whose address does not land inside the running
//     program returns 0 instead of a pointer. Every `va` in a real catalog is
//     an absolute vaddr valid for exactly one game build, and consumers read
//     the byte at a returned CALL_SITE (NCT's Catalog::LooksLikeDirectCall) —
//     against any other program that read is a SIGSEGV inside dlopen.
//
//   * `guest_exit`, the optional SECOND window an inlined WRAP target needs.
//     Exactly one shipping catalog row carries one (0x2c7f961), and it drives
//     NCT's UpdateCameraPitch EXIT cave: a half-installed entry/exit pair pins
//     the camera's pitchAdjustSpeed fields at 100000 forever
//     (BG3_NativeCameraTweaks/src/Hooks.cpp). It is bounds-checked exactly like
//     guest_entry, so both directions are asserted here.
//
//   * MALFORMED ROWS DEGRADE, THEY DO NOT ABORT. SiteCatalog::load() is
//     noexcept; a JSON `null` in a field it reads raises
//     nlohmann type_error.302, which out of a noexcept function is
//     std::terminate — the game dying at plugin load. The row below with
//     "va": null proves the per-row try/catch turns that into WARN-and-skip
//     while every other row still loads.
//
// Gate 1 (build identity) needs a whole process per catalog, because
// SiteCatalog is a singleton loaded once; its three cases live in
// test_sitecatalog_identity_ok / _mismatch / _textsize.
//
// Because of that second property the synthetic rows below are built from the
// RUNNING program's own text/data addresses rather than from round numbers
// like 0x1000: a catalog whose addresses are not in this process is exactly
// what the gate is there to reject.

#include "check.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>

// A data-segment object, so the catalog can carry a realistic Kind::Global row
// (globals live outside the executable segment and must still resolve).
static volatile std::uint64_t gSyntheticGlobal = 0;

int main()
{
	const auto base = DKUtil::Hook::Platform::ModuleBase(0);
	const auto text = DKUtil::Hook::Platform::ModuleText(0);
	CHECK(text.textxSize != 0);

	// Catalogs store UNBIASED vaddrs; resolve() adds the load bias back.
	const auto unbias = [base](std::uintptr_t a_abs) { return a_abs - base; };

	const auto equivVa = unbias(text.textx + 0x10);
	const auto inlinedVa = unbias(text.textx + 0x20);
	const auto guestVa = unbias(text.textx + 0x30);
	const auto unknownVa = unbias(text.textx + 0x40);
	const auto guestExitVa = unbias(text.textx + 0x50);
	const auto globalVa = unbias(reinterpret_cast<std::uintptr_t>(&gSyntheticGlobal));
	// Far outside any mapping of this process — the stale-catalog case.
	const auto oobVa = unbias(text.textx) + 0x4000'0000u;
	// Inside the image but not executable: a code kind must still be refused.
	const auto dataAsCodeVa = globalVa;

	const char* catalogPath = "test_sitecatalog_synthetic.json";
	{
		char   buf[4096];
		const auto n = std::snprintf(buf, sizeof(buf), R"JSON(
{
  "build_id": "cave-harness-synthetic",
  "sites": {
    "site_equiv":     { "kind": "call_site",  "relation": "equivalent",   "va": "0x%lx" },
    "site_inlined":   { "kind": "func_entry", "relation": "inlined_into", "va": "0x%lx", "guest_entry": "0x%lx" },
    "site_unknown":   { "kind": "func_entry", "relation": "unknown",      "va": "0x%lx" },
    "site_global":    { "kind": "global",     "relation": "equivalent",   "va": "0x%lx" },
    "site_oob":       { "kind": "call_site",  "relation": "equivalent",   "va": "0x%lx" },
    "site_data_code": { "kind": "call_site",  "relation": "equivalent",   "va": "0x%lx" },
    "site_wrap":      { "kind": "patch_site", "relation": "inlined_into", "va": "0x%lx", "guest_entry": "0x%lx", "guest_exit": "0x%lx" },
    "site_wrap_oob":  { "kind": "patch_site", "relation": "inlined_into", "va": "0x%lx", "guest_entry": "0x%lx", "guest_exit": "0x%lx" },
    "site_null":      { "kind": "call_site",  "relation": "equivalent",   "va": null, "len": null }
  }
}
)JSON",
			static_cast<unsigned long>(equivVa), static_cast<unsigned long>(inlinedVa),
			static_cast<unsigned long>(guestVa), static_cast<unsigned long>(unknownVa),
			static_cast<unsigned long>(globalVa), static_cast<unsigned long>(oobVa),
			static_cast<unsigned long>(dataAsCodeVa),
			// site_wrap: host + both windows in the executable segment
			static_cast<unsigned long>(inlinedVa), static_cast<unsigned long>(guestVa),
			static_cast<unsigned long>(guestExitVa),
			// site_wrap_oob: valid host + entry, but an exit outside the image
			static_cast<unsigned long>(inlinedVa), static_cast<unsigned long>(guestVa),
			static_cast<unsigned long>(oobVa));
		CHECK(n > 0 && static_cast<std::size_t>(n) < sizeof(buf));

		std::ofstream out(catalogPath, std::ios::trunc);
		out << buf;
	}
	CHECK_EQ(::setenv("DKU_SITE_CATALOG", catalogPath, 1), 0);

	auto& catalog = DKUtil::Hook::SiteCatalog::get();  // triggers load() on first access

	CHECK(catalog.loaded());
	CHECK(catalog.build_id() == "cave-harness-synthetic");
	// This catalog declares no "linux_build_id", so the identity gate cannot
	// verify it — it must say so rather than claim verification.
	CHECK(!catalog.identity_verified());

	// --- resolve(): only Relation::Equivalent hands back an address ---
	CHECK_EQ(catalog.resolve("site_equiv"), base + equivVa);
	CHECK_EQ(catalog.resolve("site_inlined"), std::uintptr_t{ 0 });  // refuses: InlinedInto
	CHECK_EQ(catalog.resolve("site_unknown"), std::uintptr_t{ 0 });  // refuses: Unknown
	CHECK_EQ(catalog.resolve("site_missing"), std::uintptr_t{ 0 });  // absent key

	// --- the bounds gate ---
	CHECK_EQ(catalog.resolve("site_global"), base + globalVa);       // .data is fine for a GLOBAL
	CHECK_EQ(catalog.resolve("site_oob"), std::uintptr_t{ 0 });      // outside the mapped image
	CHECK_EQ(catalog.resolve("site_data_code"), std::uintptr_t{ 0 });  // mapped, but not executable
	CHECK_EQ(catalog.resolve_host("site_oob"), std::uintptr_t{ 0 });

	// --- lookup(): the raw Site descriptor, for callers that need kind/
	// relation/len/index directly. It is deliberately NOT bounds-gated: it
	// reports what the file says, and resolve()/resolve_host() decide. ---
	const auto* equivSite = catalog.lookup("site_equiv");
	CHECK(equivSite != nullptr);
	CHECK(equivSite->kind == DKUtil::Hook::SiteCatalog::Kind::CallSite);
	CHECK(equivSite->relation == DKUtil::Hook::SiteCatalog::Relation::Equivalent);

	const auto* inlinedSite = catalog.lookup("site_inlined");
	CHECK(inlinedSite != nullptr);
	CHECK(inlinedSite->relation == DKUtil::Hook::SiteCatalog::Relation::InlinedInto);
	CHECK_EQ(inlinedSite->va, inlinedVa);
	CHECK_EQ(inlinedSite->guest_entry, guestVa);

	CHECK(catalog.lookup("site_missing") == nullptr);

	// --- resolve_host(): the deliberate accessor for non-equivalent sites.
	// Works for ANY site with a va (equivalent included), and reports
	// guest_entry via the out-param when present. ---
	std::uintptr_t guestEntry = 0xDEADBEEF;
	auto           hostAddr = catalog.resolve_host("site_inlined", &guestEntry);
	CHECK_EQ(hostAddr, base + inlinedVa);
	CHECK_EQ(guestEntry, base + guestVa);

	guestEntry = 0xDEADBEEF;
	auto equivHostAddr = catalog.resolve_host("site_equiv", &guestEntry);
	CHECK_EQ(equivHostAddr, base + equivVa);
	CHECK_EQ(guestEntry, std::uintptr_t{ 0 });  // equivalent sites carry no guest_entry

	CHECK_EQ(catalog.resolve_host("site_missing"), std::uintptr_t{ 0 });

	// --- guest_exit: the optional SECOND window of a WRAP target ---
	// The 3-argument resolve_host() overload. An absent guest_exit must report
	// 0 (not leave the out-param untouched), and a present, in-bounds one must
	// come back biased just like guest_entry.
	std::uintptr_t guestExit = 0xDEADBEEF;
	guestEntry = 0xDEADBEEF;
	CHECK_EQ(catalog.resolve_host("site_inlined", &guestEntry, &guestExit), base + inlinedVa);
	CHECK_EQ(guestEntry, base + guestVa);
	CHECK_EQ(guestExit, std::uintptr_t{ 0 });  // this row declares none

	guestEntry = 0xDEADBEEF;
	guestExit = 0xDEADBEEF;
	CHECK_EQ(catalog.resolve_host("site_wrap", &guestEntry, &guestExit), base + inlinedVa);
	CHECK_EQ(guestEntry, base + guestVa);
	CHECK_EQ(guestExit, base + guestExitVa);
	CHECK_EQ(catalog.lookup("site_wrap")->guest_exit, guestExitVa);

	// An out-of-bounds guest_exit is refused on its own (reported as 0 + a
	// WARN) without poisoning the host address or the good guest_entry —
	// installing an ENTRY cave with no EXIT is what pins NCT's
	// pitchAdjustSpeed fields at 100000, so this must be visible to the caller.
	guestEntry = 0xDEADBEEF;
	guestExit = 0xDEADBEEF;
	CHECK_EQ(catalog.resolve_host("site_wrap_oob", &guestEntry, &guestExit), base + inlinedVa);
	CHECK_EQ(guestEntry, base + guestVa);
	CHECK_EQ(guestExit, std::uintptr_t{ 0 });

	// --- a malformed row must not take the process down ---
	// Reaching this line at all is the assertion that matters: before the
	// per-row try/catch, "va": null threw nlohmann type_error.302 out of the
	// noexcept load(), i.e. std::terminate / SIGABRT during dlopen.
	CHECK(catalog.lookup("site_null") == nullptr);  // skipped, not stored
	CHECK_EQ(catalog.resolve("site_null"), std::uintptr_t{ 0 });
	CHECK(catalog.loaded());                        // ...and the rest still loaded
	CHECK_EQ(catalog.resolve("site_equiv"), base + equivVa);

	REPORT_AND_RETURN();
}
