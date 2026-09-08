// (1) AddRelHook / write_call<5> on a real call rel32 inside a test
// function: original callee replaced, trampoline calls original, return
// values flow.
//
// relhook_target(x) is hand-assembled (asm/targets.s) as:
//     push rbx
//     mov  ebx, edi
// relhook_callsite:
//     call original_callee        <-- E8 rel32, the site we hook
//     add  eax, ebx
//     pop  rbx
//     ret
// where original_callee(x) == x + 1000.
//
// We hook the call site to redirect to our_hook(x), which itself calls
// through to the RECOVERED original (via RelHookHandle::operator F(), the
// value AddRelHook decodes from the call's original rel32 operand before
// overwriting it) so we can prove all three things in one shot: the
// callee was replaced, the trampoline can still reach the original, and
// return values flow correctly back out through relhook_target's own
// epilogue and into the caller.

#include "check.h"
#include "targets.h"

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>

namespace
{
	using OriginalFn = int (*)(int);
	OriginalFn g_original = nullptr;
	int        g_hookCallCount = 0;

	// our_hook(x) = original(x) * 2 + 1. Distinguishable from both
	// relhook_target's un-hooked value (original(x) + x) and from
	// original(x) alone, so any of the three failure modes (hook not
	// installed / trampoline not reaching original / return value
	// mangled) produces a different, diagnosable number.
	int our_hook(int x)
	{
		++g_hookCallCount;
		int orig = g_original(x);
		return orig * 2 + 1;
	}
}  // namespace

int main()
{
	DKUtil::Hook::Trampoline::AllocTrampoline(1 << 8);

	const int x = 41;

	// Baseline: un-hooked target really does call original_callee.
	CHECK_EQ(original_callee(x), x + 1000);
	CHECK_EQ(relhook_target(x), (x + 1000) + x);

	auto callsiteAddr = reinterpret_cast<std::uintptr_t>(&relhook_callsite);

	auto handle = DKUtil::Hook::AddRelHook<5, true>(
		callsiteAddr, reinterpret_cast<std::uintptr_t>(&our_hook));

	// Recovered from the call's ORIGINAL rel32 operand, decoded by
	// AddRelHook (GetDisp) before the site was overwritten.
	g_original = reinterpret_cast<OriginalFn>(static_cast<std::uintptr_t>(handle->OriginalFunc));
	CHECK_EQ(reinterpret_cast<std::uintptr_t>(g_original), reinterpret_cast<std::uintptr_t>(&original_callee));

	handle->Enable();

	// --- replaced: relhook_target now runs our_hook instead of
	// original_callee, but relhook_target's OWN continuation after the
	// call site still runs normally ---
	int result = relhook_target(x);
	CHECK_EQ(g_hookCallCount, 1);
	// write_call<5> (N==5, RETN==true) writes a `call rel32` in place of
	// the original `call rel32` — same opcode class, so the CALL
	// instruction itself still pushes relhook_target's own return address
	// (the "add eax, ebx" instruction) onto the stack. The trampoline's
	// own branch into our_hook is a plain `jmp` (RelHook.hpp's JmpRip),
	// which pushes nothing further. So our_hook's `ret` unwinds straight
	// back to relhook_target's "add eax, ebx; pop rbx; ret" tail — this is
	// exactly the transparent "stand in for the call target, the caller's
	// surrounding code keeps running" semantics a mod hooking a subroutine
	// call actually wants. relhook_target(x) is therefore
	// our_hook(x) + x == (original(x)*2 + 1) + x, NOT our_hook(x) alone.
	CHECK_EQ(result, (x + 1000) * 2 + 1 + x);

	// --- trampoline calls original: g_original(x) still reaches the real
	// original_callee, independent of the hook rewrite ---
	CHECK_EQ(g_original(x), x + 1000);

	// --- return values flow: call again with a different input, prove
	// it's not a fluke / memoized value ---
	const int y = 7;
	CHECK_EQ(relhook_target(y), (y + 1000) * 2 + 1 + y);
	CHECK_EQ(g_hookCallCount, 2);

	handle->Disable();

	// disabled: back to the original, unhooked behavior
	CHECK_EQ(relhook_target(x), (x + 1000) + x);
	CHECK_EQ(g_hookCallCount, 2);  // our_hook not called again

	REPORT_AND_RETURN();
}
