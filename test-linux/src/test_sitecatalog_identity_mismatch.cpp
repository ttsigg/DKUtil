// (6b) SiteCatalog gate 1 — build identity, MISMATCHING build-id.
//
// The failure this gate exists to stop: Larian ships a hotfix that relinks bg3,
// the stale catalog's addresses still land inside the new image (so the bounds
// gate passes unchanged), and the mod writes through rows that now name
// entirely different objects — e.g. NCT's SetCameraSettings writing ~30 floats
// into whatever `ls::GlobalSwitches`' old slot now holds.
//
// Refusal must be TOTAL: not a warning, not a partial load. `loaded()` stays
// false, `_sites` stays empty, and every resolve()/resolve_host() returns 0, so
// each hook takes its normal WARN-and-skip path and the game still boots.
//
// Own executable because SiteCatalog::load() runs once per process.

#include "check.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>

int main()
{
	const auto base = DKUtil::Hook::Platform::ModuleBase(0);
	const auto text = DKUtil::Hook::Platform::ModuleText(0);
	CHECK(text.textxSize != 0);

	const auto equivVa = (text.textx + 0x10) - base;

	// A syntactically valid 20-byte build-id that is not this program's. (If
	// this binary happens to carry no build-id note at all, gate 1 refuses for
	// the other documented reason — "declares an id but the program has none" —
	// and every assertion below still holds.)
	static constexpr const char* kWrongId = "0123456789abcdef0123456789abcdef01234567";

	const char* catalogPath = "test_sitecatalog_identity_mismatch.json";
	{
		char       buf[1024];
		const auto n = std::snprintf(buf, sizeof(buf),
			"{\n"
			"  \"build_id\": \"cave-harness-identity-mismatch\",\n"
			"  \"linux_build_id\": \"%s\",\n"
			"  \"sites\": {\n"
			"    \"site_equiv\":  { \"kind\": \"call_site\",  \"relation\": \"equivalent\",   \"va\": \"0x%lx\" },\n"
			"    \"site_global\": { \"kind\": \"global\",     \"relation\": \"equivalent\",   \"va\": \"0x%lx\" }\n"
			"  }\n"
			"}\n",
			kWrongId, static_cast<unsigned long>(equivVa), static_cast<unsigned long>(equivVa));
		CHECK(n > 0 && static_cast<std::size_t>(n) < sizeof(buf));

		std::ofstream out(catalogPath, std::ios::trunc);
		out << buf;
	}
	CHECK_EQ(::setenv("DKU_SITE_CATALOG", catalogPath, 1), 0);

	auto& catalog = DKUtil::Hook::SiteCatalog::get();

	CHECK(!catalog.loaded());
	CHECK(!catalog.identity_verified());

	// Nothing resolves — including a `global` row, which has no second content
	// check of its own anywhere downstream.
	CHECK_EQ(catalog.resolve("site_equiv"), std::uintptr_t{ 0 });
	CHECK_EQ(catalog.resolve("site_global"), std::uintptr_t{ 0 });
	CHECK_EQ(catalog.resolve_host("site_equiv"), std::uintptr_t{ 0 });
	CHECK(catalog.lookup("site_equiv") == nullptr);

	REPORT_AND_RETURN();
}
