// (6c) SiteCatalog gate 1 — build identity via linux_text_size.
//
// The secondary identity check, for a rebuild that somehow kept its build-id
// (or a program that carries no build-id note at all): the size of the largest
// PF_X PT_LOAD segment, which is what Platform::ModuleText(0).textxSize reports
// and what gen_site_catalog.py::linux_identity() reads out of the bg3 ELF.
//
// Proves the NEGATIVE direction independently of the build-id: a declared text
// size that does not match refuses the whole catalog, exactly as a wrong
// build-id does. (The positive direction is test_sitecatalog_identity_ok, which
// declares this field too.)
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

	const char* catalogPath = "test_sitecatalog_identity_textsize.json";
	{
		char       buf[1024];
		const auto n = std::snprintf(buf, sizeof(buf),
			"{\n"
			"  \"build_id\": \"cave-harness-identity-textsize\",\n"
			"  \"linux_text_size\": %zu,\n"
			"  \"sites\": {\n"
			"    \"site_equiv\": { \"kind\": \"call_site\", \"relation\": \"equivalent\", \"va\": \"0x%lx\" }\n"
			"  }\n"
			"}\n",
			text.textxSize + 0x1000, static_cast<unsigned long>(equivVa));
		CHECK(n > 0 && static_cast<std::size_t>(n) < sizeof(buf));

		std::ofstream out(catalogPath, std::ios::trunc);
		out << buf;
	}
	CHECK_EQ(::setenv("DKU_SITE_CATALOG", catalogPath, 1), 0);

	auto& catalog = DKUtil::Hook::SiteCatalog::get();

	CHECK(!catalog.loaded());
	CHECK(!catalog.identity_verified());
	CHECK_EQ(catalog.resolve("site_equiv"), std::uintptr_t{ 0 });
	CHECK(catalog.lookup("site_equiv") == nullptr);

	REPORT_AND_RETURN();
}
