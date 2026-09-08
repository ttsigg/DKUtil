// (3b) AddCaveHook: displaced ("stolen") instructions containing a
// RIP-relative operand.
//
// PART A (positive): ripcave_site (asm/targets.s) holds exactly one 7-byte
// instruction:
//     lea rax, [rip + g_rip_target_value]
// We cave-hook it with HookFlag::kRestoreBeforeProlog, which makes
// CaveHookHandle replay the stolen bytes into the trampoline via
// Internal/CaveHook.hpp's detail::WriteRelocatedStolenBytes -- which decodes
// the stolen range and rewrites any RIP-relative disp32 for the trampoline's
// address instead of a raw memcpy. Our own prolog then immediately snapshots
// whatever ended up in rax into g_observed_rip_value, before anything else
// (including the callback) can touch rax. The replayed `lea` must compute
// the SAME absolute address it did at its original site, even though it now
// runs from a completely different address (the trampoline, potentially
// hundreds of MB away -- Trampoline::PageAlloc's choice).
//
// PART B (negative): undecodable_cave_site (asm/targets.s) holds one
// `call qword ptr [rip+g_call_target_ptr]` (FF 15 <disp32>) -- an opcode
// outside the minimal decoder's known set. AddCaveHook must refuse this
// hook outright (return a null/skip handle, Address == 0) rather than
// replay or guess-relocate an instruction it cannot prove is safe. See
// docs/linux-port/CAVE-HOOKS.md "RIP-relative stolen bytes" for the
// rule this enforces.
//
// PART C (positive, opcode 0x63): movsxdcave_site (asm/targets.s) holds
// exactly one 7-byte instruction:
//     movsxd rax, dword ptr [rip + g_movsxd_source]
// Added 2026-09-07 after the WASD InsideUpdateInteractMove cave (tracker
// key 0x1420626e0) turned out to steal a `movsxd rcx,[rdi+0x130]` --
// opcode 0x63, which DecodeStolenInsn refused before this test, making
// AddCaveHook silently return a null handle for that hook. Same relocation
// path as Part A's `lea` (ModRM mod=00,rm=101, disp32 immediately after),
// but a distinct opcode with a distinct decode-length pitfall: movsxd's
// destination (rax, 64-bit) is wider than its source operand (r/m32), so a
// decoder that mismeasured it as a plain 4-byte-result `mov` would still
// produce a plausible-looking but wrong value. g_movsxd_source is a
// negative sentinel so a dropped sign-extend shows up as a wrong observed
// value instead of accidentally matching.

#include "check.h"
#include "targets.h"

#include <cstring>

#define PROJECT_NAME "cave-harness"
#include <DKUtil/Hook.hpp>
#include <xbyak/xbyak.h>

namespace
{
	// Snapshot rax into g_observed_rip_value the instant control reaches
	// the trampoline's prolog -- i.e. immediately after the replayed
	// (relocated) `lea` runs and before DKUtil's own stack-alloc/call/
	// dealloc sequence or the callback gets a chance to touch rax.
	struct SnapshotRaxProlog : Xbyak::CodeGenerator
	{
		SnapshotRaxProlog()
		{
			using namespace Xbyak::util;
			mov(rcx, reinterpret_cast<uint64_t>(&g_observed_rip_value));
			mov(ptr[rcx], rax);
		}
	};

	// Same idea as SnapshotRaxProlog, into g_observed_movsxd_value for Part C.
	struct SnapshotRaxMovsxdProlog : Xbyak::CodeGenerator
	{
		SnapshotRaxMovsxdProlog()
		{
			using namespace Xbyak::util;
			mov(rcx, reinterpret_cast<uint64_t>(&g_observed_movsxd_value));
			mov(ptr[rcx], rax);
		}
	};
}  // namespace

int main()
{
	DKUtil::Hook::Trampoline::AllocTrampoline(1 << 8);

	// ---- Part A: a decodable RIP-relative instruction is relocated, not
	// replayed verbatim -------------------------------------------------
	{
		auto address = reinterpret_cast<std::uintptr_t>(&ripcave_target);
		auto siteOff = reinterpret_cast<std::uintptr_t>(&ripcave_site) - address;
		auto endOff = reinterpret_cast<std::uintptr_t>(&ripcave_site_end) - address;
		CHECK(endOff - siteOff == 7);  // 48 8D 05 <disp32>

		SnapshotRaxProlog prolog;

		auto handle = DKUtil::Hook::AddCaveHook(
			address,
			{ static_cast<std::ptrdiff_t>(siteOff), static_cast<std::ptrdiff_t>(endOff) },
			RT_INFO(&ripcave_noop_callback, "ripcave_noop_callback"),
			&prolog, nullptr,
			DKUtil::Hook::HookFlag::kRestoreBeforeProlog);

		// A decodable stolen instruction must not be refused.
		CHECK(handle->Address != 0);

		// OldBytes is captured at construction, before Enable() overwrites
		// the site -- read the ORIGINAL instruction's disp32 straight from
		// it so the "correct address" derivation below doesn't depend on
		// us re-deriving the assembler's own arithmetic by hand.
		CHECK_EQ(handle->OldBytes.size(), std::size_t{ 7 });
		std::int32_t originalDisp = 0;
		std::memcpy(&originalDisp, handle->OldBytes.data() + 3, sizeof(originalDisp));

		const auto correctAddr = reinterpret_cast<std::uintptr_t>(&g_rip_target_value);
		// Sanity: the assembler's encoding really does describe the real target.
		CHECK_EQ(reinterpret_cast<std::uintptr_t>(&ripcave_site) + 7 + originalDisp, correctAddr);

		// What the OLD naive-memcpy replay would have computed instead --
		// kept only to prove the fixed behavior actually differs from it.
		const auto replayAddr = handle->TramEntry;
		const auto naiveWrongAddr = replayAddr + 7 + static_cast<std::uintptr_t>(originalDisp);

		handle->Enable();
		ripcave_target();
		handle->Disable();

		// The relocated `lea`, replayed at a different address, must still
		// compute the ORIGINAL absolute target.
		CHECK_EQ(g_observed_rip_value, correctAddr);
		CHECK(g_observed_rip_value != naiveWrongAddr);
	}

	// ---- Part B: an undecodable stolen instruction is refused, not
	// silently replayed -------------------------------------------------
	{
		auto address = reinterpret_cast<std::uintptr_t>(&undecodable_cave_target);
		auto siteOff = reinterpret_cast<std::uintptr_t>(&undecodable_cave_site) - address;
		auto endOff = reinterpret_cast<std::uintptr_t>(&undecodable_cave_site_end) - address;
		CHECK(endOff - siteOff == 6);  // FF 15 <disp32>

		SnapshotRaxProlog prolog;  // irrelevant here; the hook must never install

		auto handle = DKUtil::Hook::AddCaveHook(
			address,
			{ static_cast<std::ptrdiff_t>(siteOff), static_cast<std::ptrdiff_t>(endOff) },
			RT_INFO(&ripcave_noop_callback, "ripcave_noop_callback"),
			&prolog, nullptr,
			DKUtil::Hook::HookFlag::kRestoreBeforeProlog);

		// AddCaveHook must refuse rather than guess: a null/skip handle,
		// same convention as an unresolved catalog site.
		CHECK_EQ(handle->Address, std::uintptr_t{ 0 });

		// Enable() on a refused handle must be a safe no-op -- it must NOT
		// patch the (never-decoded) call site.
		handle->Enable();
		handle->Disable();
	}

	// ---- Part C: opcode 0x63 (movsxd r64, r/m32) with a RIP-relative
	// operand is relocated, not refused --------------------------------
	{
		auto address = reinterpret_cast<std::uintptr_t>(&movsxdcave_target);
		auto siteOff = reinterpret_cast<std::uintptr_t>(&movsxdcave_site) - address;
		auto endOff = reinterpret_cast<std::uintptr_t>(&movsxdcave_site_end) - address;
		CHECK(endOff - siteOff == 7);  // 48 63 05 <disp32>

		SnapshotRaxMovsxdProlog prolog;

		auto handle = DKUtil::Hook::AddCaveHook(
			address,
			{ static_cast<std::ptrdiff_t>(siteOff), static_cast<std::ptrdiff_t>(endOff) },
			RT_INFO(&movsxdcave_noop_callback, "movsxdcave_noop_callback"),
			&prolog, nullptr,
			DKUtil::Hook::HookFlag::kRestoreBeforeProlog);

		// Opcode 0x63 must now be accepted, not refused.
		CHECK(handle->Address != 0);

		CHECK_EQ(handle->OldBytes.size(), std::size_t{ 7 });
		std::int32_t originalDisp = 0;
		std::memcpy(&originalDisp, handle->OldBytes.data() + 3, sizeof(originalDisp));
		const auto correctSrcAddr = reinterpret_cast<std::uintptr_t>(&g_movsxd_source);
		CHECK_EQ(reinterpret_cast<std::uintptr_t>(&movsxdcave_site) + 7 + originalDisp, correctSrcAddr);

		// The value the replayed `movsxd` must read and sign-extend, sign
		// extension done in C++ so the check doesn't depend on us
		// re-deriving the CPU's own arithmetic by hand.
		const auto expected = static_cast<std::uint64_t>(static_cast<std::int64_t>(g_movsxd_source));

		handle->Enable();
		movsxdcave_target();
		handle->Disable();

		// The relocated `movsxd`, replayed at a different address, must
		// still read the ORIGINAL rip-relative operand and sign-extend it
		// to 64 bits correctly.
		CHECK_EQ(g_observed_movsxd_value, expected);
	}

	REPORT_AND_RETURN();
}
