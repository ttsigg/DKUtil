// (2) AddASMPatch at a mid-function site.
//
// asmpatch_target() is hand-assembled (asm/targets.s) as:
//     mov eax, 7
// asmpatch_site:
//     <16 bytes of NOP>
// asmpatch_site_end:
//     add eax, 1
//     ret
// so un-patched it returns 8. We patch the first bytes of the NOP run
// in-place with `add eax, 100` (built via Xbyak, mirroring how a real mod
// supplies a patch) and prove: the function's return value reflects the
// patch (107 + the trailing "add eax,1" = 108), the patch can be disabled
// back to the original NOPs (returns 8 again), and the patch correctly
// leaves the untouched tail of the cave (and the "add eax,1; ret" after
// it) intact — i.e. this is a genuine in-place byte patch mid-function,
// not a full function replacement.

#include "check.h"
#include "targets.h"

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>
#include <xbyak/xbyak.h>

namespace
{
	struct AddPatch : Xbyak::CodeGenerator
	{
		AddPatch()
		{
			using namespace Xbyak::util;
			add(eax, 100);
		}
	};
}  // namespace

int main()
{
	DKUtil::Hook::Trampoline::AllocTrampoline(1 << 8);

	CHECK_EQ(asmpatch_target(), 8);

	auto address = reinterpret_cast<std::uintptr_t>(&asmpatch_target);
	auto siteOff = reinterpret_cast<std::uintptr_t>(&asmpatch_site) - address;
	auto endOff = reinterpret_cast<std::uintptr_t>(&asmpatch_site_end) - address;
	CHECK(endOff - siteOff == 16);

	AddPatch patch;
	CHECK(patch.getSize() <= (endOff - siteOff));  // must fit without a trampoline fallback

	auto handle = DKUtil::Hook::AddASMPatch(address, { static_cast<std::ptrdiff_t>(siteOff), static_cast<std::ptrdiff_t>(endOff) }, &patch);

	handle->Enable();
	CHECK_EQ(asmpatch_target(), 108);

	handle->Disable();
	CHECK_EQ(asmpatch_target(), 8);

	// re-enable, prove it's idempotent / re-armable
	handle->Enable();
	CHECK_EQ(asmpatch_target(), 108);

	REPORT_AND_RETURN();
}
