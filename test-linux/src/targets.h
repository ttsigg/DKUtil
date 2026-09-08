// Hand-written x86-64 test targets (asm/targets.s) and the C++ globals that
// glue the asm to the test drivers. Everything here is deliberately real
// machine code, not compiler output — a cave/patch/call-site hooking test
// needs byte-exact control over what is at the hook address, and relying on
// whatever a given compiler version happens to emit for a C++ function is
// exactly the kind of thing that breaks silently across toolchain bumps.
//
// Labels are exported as ordinary global symbols so the test drivers can
// take their address with `&label` and compute offsets by pointer
// subtraction — no objdump, no hardcoded byte offsets.
#pragma once

#include <cstdint>

extern "C" {

// ---- RelHook / write_call<5> target -----------------------------------
// relhook_target(x) == original_callee(x) + x, where original_callee is a
// real `call rel32` at relhook_callsite (exactly 5 bytes: E8 + rel32).
int original_callee(int x);
int relhook_target(int x);
void relhook_callsite();  // address of the `call original_callee` instruction

// ---- AddASMPatch target -------------------------------------------------
// asmpatch_target() == 8, computed as `mov eax,7` then a run of NOPs
// [asmpatch_site, asmpatch_site_end) then `add eax,1; ret`.
int  asmpatch_target();
void asmpatch_site();
void asmpatch_site_end();

// ---- AddCaveHook target: SysV register / SSE preservation --------------
// cavehook_target() sets sentinel values into rbx/rbp/r12-r15/xmm6, runs
// through the cave [cavehook_site, cavehook_site_end) (16 NOPs), then
// stores whatever those registers hold AFTER the cave into g_post[] and
// returns. cavehook_callback (also hand-written, no compiler-generated
// save/restore) reads the prolog's g_pre[] snapshot into g_observed[],
// then deliberately clobbers rbx/rbp/r12-r15/xmm6 with garbage to prove
// it's the fork's own generated epilog — not incidental ABI behavior —
// that must restore them.
void cavehook_target();  // returns nothing; results land in g_pre/g_post/g_observed
void cavehook_site();
void cavehook_site_end();
void cavehook_callback();

// 6 slots: rbx, rbp, r12, r13, r14, r15, then one more (index 6) for the
// xmm6 lane stored as a raw u64 via movq. 7 * 8 bytes each.
extern uint64_t g_pre[7];
extern uint64_t g_post[7];
extern uint64_t g_observed[7];
extern uint64_t g_callback_rsp_align;  // rsp & 0xF observed inside the callback

// ---- AddCaveHook target: stolen RIP-relative instruction ---------------
// ripcave_site holds exactly one instruction: `lea rax, [rip + g_rip_target_value]`
// (7 bytes: 48 8D 05 <disp32>). The cave-hook test steals just this
// instruction (kRestoreBeforeProlog) so it gets replayed verbatim inside
// the trampoline, at a different address than where the assembler computed
// its displacement for — proving whether the fork relocates RIP-relative
// stolen bytes.
void ripcave_target();
void ripcave_site();
void ripcave_site_end();  // == ripcave_site + 7
void ripcave_noop_callback();

extern uint64_t g_rip_target_value;   // the LEA's real target; a known sentinel
extern uint64_t g_observed_rip_value; // what the replayed LEA actually computed

// ---- AddCaveHook target: stolen movsxd (opcode 0x63) RIP-relative ------
// movsxdcave_site holds exactly one instruction:
// `movsxd rax, dword ptr [rip + g_movsxd_source]` (7 bytes: 48 63 05
// <disp32>). Proves DecodeStolenInsn's opcode-0x63 acceptance: the cave
// steals just this instruction (kRestoreBeforeProlog), replaying it at a
// different (trampoline) address, and the result must still be the
// correctly-addressed, correctly-sign-extended value of g_movsxd_source --
// not a value read from the wrong address (proves relocation) and not a
// truncated/zero-extended one (proves the decoder measured the full 7-byte
// instruction, not a shorter guess).
void movsxdcave_target();
void movsxdcave_site();
void movsxdcave_site_end();  // == movsxdcave_site + 7
void movsxdcave_noop_callback();

extern int32_t  g_movsxd_source;          // a negative sentinel, to catch a missing sign-extend
extern uint64_t g_observed_movsxd_value;  // what the replayed movsxd actually computed

// ---- AddCaveHook target: undecodable stolen instruction (negative case) --
// undecodable_cave_site holds a single `call qword ptr [rip+g_call_target_ptr]`
// (FF 15 <disp32>, 6 bytes) -- an opcode outside the minimal decoder's known
// set (Internal/CaveHook.hpp DecodeStolenInsn). AddCaveHook must refuse this
// hook (return a null/skip handle) rather than replay it byte-for-byte or
// guess at relocating it. Never invoked: the whole point of the test is that
// the hook install fails before Enable() ever patches the site.
void undecodable_cave_target();
void undecodable_cave_site();
void undecodable_cave_site_end();  // == undecodable_cave_site + 6

extern uint64_t g_call_target_ptr;  // never dereferenced; just needs to exist

}  // extern "C"
