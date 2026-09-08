// Minimal, dependency-free check macros for the cave-harness ctest
// binaries. No test framework is vendored into Linux/deps, and these
// binaries are simple enough (one property proven per executable) that a
// framework would be pure overhead — this mirrors the workspace's existing
// style for small ctest probes (bg3mods_loader/test/attach_probe.cpp).
#pragma once

#include <cstdio>
#include <cstdlib>

inline int g_checkFailures = 0;

#define CHECK(cond)                                                                    \
	do {                                                                                \
		if (!(cond)) {                                                                 \
			std::fprintf(stderr, "[FAIL] %s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
			++g_checkFailures;                                                          \
		} else {                                                                       \
			std::fprintf(stderr, "[ pass] %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
		}                                                                               \
	} while (0)

#define CHECK_EQ(a, b)                                                                                     \
	do {                                                                                                    \
		auto _a = (a);                                                                                     \
		auto _b = (b);                                                                                     \
		if (!(_a == _b)) {                                                                                 \
			std::fprintf(stderr, "[FAIL] %s:%d: CHECK_EQ(%s, %s) : 0x%llx != 0x%llx\n", __FILE__, __LINE__, \
				#a, #b, (unsigned long long)_a, (unsigned long long)_b);                                    \
			++g_checkFailures;                                                                             \
		} else {                                                                                           \
			std::fprintf(stderr, "[ pass] %s:%d: %s == %s (0x%llx)\n", __FILE__, __LINE__, #a, #b,          \
				(unsigned long long)_a);                                                                    \
		}                                                                                                  \
	} while (0)

#define REPORT_AND_RETURN()                                                            \
	do {                                                                                \
		if (g_checkFailures) {                                                         \
			std::fprintf(stderr, "\n%d check(s) FAILED\n", g_checkFailures);           \
			return 1;                                                                  \
		}                                                                               \
		std::fprintf(stderr, "\nall checks passed\n");                                 \
		return 0;                                                                      \
	} while (0)
