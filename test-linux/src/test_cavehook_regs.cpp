// (3a) AddCaveHook at a mid-function {low,high} offset with an
// Xbyak::CodeGenerator prolog/epilog under the SysV ABI: prove the cave
// preserves rbp/rbx/r12-r15 and the SSE state it says it preserves, and
// that a callback reading a register snapshot sees the expected values.
//
// cavehook_target() (asm/targets.s) sets sentinel values into
// rbx/rbp/r12-r15/xmm6, runs through a 16-byte NOP cave, then stores
// whatever those registers hold AFTER the cave into g_post[] and returns.
//
// Our own Xbyak prolog (below) pushes rbx/rbp/r12-r15 and saves xmm6 to
// the stack, then snapshots all of them into g_pre[] BEFORE calling the
// hook. The hook callback (cavehook_callback, hand-written in asm/targets.s
// — see the comment there for why it must not be compiler-generated) reads
// g_pre[] into g_observed[] and then deliberately clobbers rbx/rbp/r12-r15
// and xmm6 with garbage. Our epilog pops/restores them from the stack. If
// g_post[] (captured by the host AFTER the whole cave) still matches the
// sentinels the host set BEFORE the cave, the fork's cave-hook trampoline
// — specifically the prolog/epilog WE authored, run around DKUtil's own
// stack-alloc + `call [rip]` — is what put them back, not incidental ABI
// behavior (the callback is hand-written asm with no compiler epilogue of
// its own to fall back on).

#include "check.h"
#include "targets.h"

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>
#include <xbyak/xbyak.h>

namespace
{
	constexpr uint64_t kRbx = 0x1111111111111111ull;
	constexpr uint64_t kRbp = 0x2222222222222222ull;
	constexpr uint64_t kR12 = 0x3333333333333333ull;
	constexpr uint64_t kR13 = 0x4444444444444444ull;
	constexpr uint64_t kR14 = 0x5555555555555555ull;
	constexpr uint64_t kR15 = 0x6666666666666666ull;
	constexpr uint64_t kXmm6AsU64 = 0x77777777AAAAAAAAull;

	// Prolog: preserve rbx/rbp/r12-r15 (push) and xmm6 (stack-saved — SysV
	// gives XMM registers NO callee-saved guarantee at all, so unlike the
	// GPRs, an ordinary compiled callee is free to clobber xmm6 with zero
	// obligation to restore it; only an explicit save/restore like this
	// one protects it), then snapshot all seven values into g_pre[] via an
	// absolute address in a scratch register (rax — deliberately NOT
	// preserved: it's caller-saved in the *host's* own convention wherever
	// a cave point like this would legitimately be chosen, and DKUtil's
	// own generated code around us doesn't rely on it either).
	struct RegsProlog : Xbyak::CodeGenerator
	{
		RegsProlog()
		{
			using namespace Xbyak::util;
			push(rbx);
			push(rbp);
			push(r12);
			push(r13);
			push(r14);
			push(r15);
			sub(rsp, 16);
			movdqu(ptr[rsp], xmm6);

			mov(rax, reinterpret_cast<uint64_t>(&g_pre));
			mov(ptr[rax + 0], rbx);
			mov(ptr[rax + 8], rbp);
			mov(ptr[rax + 16], r12);
			mov(ptr[rax + 24], r13);
			mov(ptr[rax + 32], r14);
			mov(ptr[rax + 40], r15);
			movq(ptr[rax + 48], xmm6);
		}
	};

	// Epilog: restore in exactly reverse order, undoing the prolog's own
	// stack adjustments (16 bytes for xmm6, then 6*8 for the GPRs) — this
	// must be a mirror image or the trampoline's own `jmp` back into the
	// host runs on a corrupted stack.
	struct RegsEpilog : Xbyak::CodeGenerator
	{
		RegsEpilog()
		{
			using namespace Xbyak::util;
			movdqu(xmm6, ptr[rsp]);
			add(rsp, 16);
			pop(r15);
			pop(r14);
			pop(r13);
			pop(r12);
			pop(rbp);
			pop(rbx);
		}
	};
}  // namespace

int main()
{
	DKUtil::Hook::Trampoline::AllocTrampoline(1 << 9);

	auto address = reinterpret_cast<std::uintptr_t>(&cavehook_target);
	auto siteOff = reinterpret_cast<std::uintptr_t>(&cavehook_site) - address;
	auto endOff = reinterpret_cast<std::uintptr_t>(&cavehook_site_end) - address;
	CHECK(endOff - siteOff == 16);

	RegsProlog prolog;
	RegsEpilog epilog;

	auto handle = DKUtil::Hook::AddCaveHook(
		address,
		{ static_cast<std::ptrdiff_t>(siteOff), static_cast<std::ptrdiff_t>(endOff) },
		RT_INFO(&cavehook_callback, "cavehook_callback"),
		&prolog, &epilog);

	handle->Enable();

	cavehook_target();

	// --- the callback saw the live values via the snapshot our prolog
	// built (this IS "a callback reading a register snapshot sees the
	// expected values" — cavehook_callback has no other way to see them,
	// it never receives them as call arguments) ---
	CHECK_EQ(g_observed[0], kRbx);
	CHECK_EQ(g_observed[1], kRbp);
	CHECK_EQ(g_observed[2], kR12);
	CHECK_EQ(g_observed[3], kR13);
	CHECK_EQ(g_observed[4], kR14);
	CHECK_EQ(g_observed[5], kR15);
	CHECK_EQ(g_observed[6], kXmm6AsU64);

	// --- the callback (hand-written, no compiler safety net) DID clobber
	// rbx/rbp/r12-r15/xmm6 with 0xDEAD.../0 internally; g_post[] is what
	// the host sees after the WHOLE cave (prolog, call, epilog) returns
	// control to it. If these still match the pre-cave sentinels, only
	// the fork's cave-hook mechanism running our push/pop prolog+epilog
	// around the call explains it. ---
	CHECK_EQ(g_post[0], kRbx);
	CHECK_EQ(g_post[1], kRbp);
	CHECK_EQ(g_post[2], kR12);
	CHECK_EQ(g_post[3], kR13);
	CHECK_EQ(g_post[4], kR14);
	CHECK_EQ(g_post[5], kR15);
	CHECK_EQ(g_post[6], kXmm6AsU64);

	// --- secondary finding: SysV requires rsp % 16 == 0 immediately
	// before a `call`. DKUtil's own ASM_STACK_ALLOC_SIZE (0x20) is
	// alignment-neutral (even), so it's our prolog's job to keep the
	// total pushed byte count a multiple of 16 too (6*8 + 16 == 64 here).
	// A misaligned stack at the `call [rip]` would silently corrupt any
	// SSE instruction inside a compiled hook callback that assumes
	// alignment (movaps, etc.) ---
	CHECK_EQ(g_callback_rsp_align, 0ull);

	handle->Disable();

	REPORT_AND_RETURN();
}
