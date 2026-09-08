#include "targets.h"

extern "C" {

uint64_t g_pre[7]{};
uint64_t g_post[7]{};
uint64_t g_observed[7]{};
uint64_t g_callback_rsp_align{ 0xFFFFFFFFFFFFFFFFull };

uint64_t g_rip_target_value{ 0x1122334455667788ull };
uint64_t g_observed_rip_value{ 0 };

// Negative so a decoder bug that dropped the sign-extend (or measured the
// instruction as a plain 32-bit `mov` instead of `movsxd`) would show up
// as a wrong (positive/truncated) observed value instead of accidentally
// matching.
int32_t  g_movsxd_source{ -12345 };
uint64_t g_observed_movsxd_value{ 0 };

uint64_t g_call_target_ptr{ 0 };

}  // extern "C"
