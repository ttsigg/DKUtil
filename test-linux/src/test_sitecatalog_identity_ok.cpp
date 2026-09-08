// (6a) SiteCatalog gate 1 — build identity, MATCHING case.
//
// SiteCatalog.hpp's first gate exists because a catalog generated for game
// build N, loaded against a game patched to N+1, does not fail loudly: every
// absolute `va` still lands inside the new image, so gate 2 (bounds) passes and
// resolve() hands back live addresses for entirely different code. Only the
// ELF's GNU build-id can tell the two apart.
//
// SiteCatalog is a singleton whose load() runs once per process, so each gate-1
// case needs its own executable. This one proves the POSITIVE direction: a
// catalog that declares the running program's own identity loads AND reports
// identity_verified() — as opposed to the "NOT DECLARED — unverifiable" path
// that test_sitecatalog.cpp covers.
//
// The identity is read from the running binary itself
// (SiteCatalog::running_build_id() / Platform::ModuleText), which is exactly
// what docs/linux-port/tools/gen_site_catalog.py::linux_identity() writes into
// the shipping catalog from the bg3 ELF.

#include "check.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>

int main()
{
	const auto base = DKUtil::Hook::Platform::ModuleBase(0);
	const auto text = DKUtil::Hook::Platform::ModuleText(0);
	CHECK(text.textxSize != 0);

	const auto  equivVa = (text.textx + 0x10) - base;
	const auto& runningId = DKUtil::Hook::SiteCatalog::running_build_id();

	// A test binary built without --build-id has no note to compare against.
	// linux_text_size alone still arms the gate, so declare whichever fields
	// this binary can actually offer.
	std::string idField;
	if (!runningId.empty()) {
		idField = "  \"linux_build_id\": \"" + runningId + "\",\n";
	} else {
		std::fprintf(stderr,
			"[note] this binary carries no GNU build-id note; exercising gate 1 through "
			"linux_text_size only\n");
	}

	const char* catalogPath = "test_sitecatalog_identity_ok.json";
	{
		char       buf[1024];
		const auto n = std::snprintf(buf, sizeof(buf),
			"{\n"
			"  \"build_id\": \"cave-harness-identity-ok\",\n"
			"%s"
			"  \"linux_text_size\": %zu,\n"
			"  \"sites\": {\n"
			"    \"site_equiv\": { \"kind\": \"call_site\", \"relation\": \"equivalent\", \"va\": \"0x%lx\" }\n"
			"  }\n"
			"}\n",
			idField.c_str(), text.textxSize, static_cast<unsigned long>(equivVa));
		CHECK(n > 0 && static_cast<std::size_t>(n) < sizeof(buf));

		std::ofstream out(catalogPath, std::ios::trunc);
		out << buf;
	}
	CHECK_EQ(::setenv("DKU_SITE_CATALOG", catalogPath, 1), 0);

	auto& catalog = DKUtil::Hook::SiteCatalog::get();

	CHECK(catalog.loaded());
	CHECK(catalog.build_id() == "cave-harness-identity-ok");
	// The whole point: a declared, matching identity must report VERIFIED, not
	// merely "loaded". Nothing downstream can tell the difference otherwise.
	CHECK(catalog.identity_verified());
	if (!runningId.empty()) {
		CHECK(catalog.linux_build_id() == runningId);
	}

	// ...and a verified catalog still resolves normally.
	CHECK_EQ(catalog.resolve("site_equiv"), base + equivVa);

	REPORT_AND_RETURN();
}
