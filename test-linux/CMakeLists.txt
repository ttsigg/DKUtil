cmake_minimum_required(VERSION 3.19)

# Standalone Linux ctest harness proving the DKUtil fork's (branch
# linux-port) hook mechanisms end-to-end: AddRelHook/write_call, AddASMPatch,
# AddCaveHook (SysV register/SSE preservation + the RIP-relative
# stolen-bytes trap), the Trampoline/Xbyak W^X posture, and SiteCatalog
# resolve()/resolve_host().
#
# This mirrors bg3mods_loader's and BG3_NativeCameraTweaks/cmake/linux's
# pattern: an in-container g++ build is a compile+run correctness check
# (there is no game binary here — every target is a hand-assembled local
# test function; nothing about this harness needs the sniper sysroot).
#
# Build + run:
#   cmake -B build -G Ninja -S DKUtil/test-linux -DCMAKE_CXX_COMPILER=g++
#   cmake --build build
#   ctest --test-dir build --output-on-failure
#
# See ../../docs/linux-port/CAVE-HOOKS.md for what each test proves and why.

project(dkutil_cave_harness CXX ASM)

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
	message(FATAL_ERROR "In-source builds are not allowed.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- layout ---------------------------------------------------------------
# This file lives at DKUtil/test-linux/CMakeLists.txt. The fork itself is
# the parent directory; deps come from the workspace-root Linux/deps
# fetch_deps.sh output, matching BG3_NativeCameraTweaks/cmake/linux and
# bg3mods_loader.
set(DKUTIL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Path to the DKUtil fork root")
get_filename_component(DKUTIL_ROOT "${DKUTIL_ROOT}" ABSOLUTE)

set(WORKSPACE_ROOT "${DKUTIL_ROOT}/.." CACHE PATH "Path to the bg3_mods workspace root")
get_filename_component(WORKSPACE_ROOT "${WORKSPACE_ROOT}" ABSOLUTE)

set(DEPS_ROOT "${WORKSPACE_ROOT}/Linux/deps" CACHE PATH "Path to fetch_deps.sh's output directory")

if(NOT EXISTS "${DKUTIL_ROOT}/include/DKUtil/Hook.hpp")
	message(FATAL_ERROR
		"DKUtil fork not found at ${DKUTIL_ROOT} (expected include/DKUtil/Hook.hpp). "
		"Pass -DDKUTIL_ROOT=<path> to override.")
endif()

foreach(dep_hdr
	"spdlog/include/spdlog/spdlog.h"
	"xbyak/xbyak/xbyak.h"
	"nlohmann/json.hpp")
	if(NOT EXISTS "${DEPS_ROOT}/${dep_hdr}")
		message(FATAL_ERROR
			"Dependency header ${dep_hdr} not found under ${DEPS_ROOT}. "
			"Run docs/linux-port/tools/fetch_deps.sh first. "
			"Pass -DDEPS_ROOT=<path> to override.")
	endif()
endforeach()

# --- shared test-target object library ------------------------------------
# The hand-assembled x86-64 test functions (asm/targets.s) and the C++
# globals that glue them to the drivers (src/globals.cpp), built once and
# linked into every test binary below.
add_library(cave_harness_targets OBJECT
	asm/targets.s
	src/globals.cpp
)
target_include_directories(cave_harness_targets PRIVATE src)

set(CAVE_HARNESS_INCLUDES
	"${DKUTIL_ROOT}/include"
	"${DKUTIL_ROOT}/include/external"
	"${DEPS_ROOT}/spdlog/include"
	"${DEPS_ROOT}/xbyak"
	"${DEPS_ROOT}"  # nlohmann/json.hpp -> <nlohmann/json.hpp>
)

# PROJECT_NAME is `#define`d in each test .cpp before it includes
# DKUtil/Hook.hpp (Logger.hpp needs it as a string-literal expression) —
# not set here, to avoid a command-line-vs-source macro redefinition
# mismatch.
set(CAVE_HARNESS_DEFS
	SPDLOG_HEADER_ONLY
	PLUGIN_MODE
	# The Steam sniper SDK's gcc-14 libstdc++ auto-enables its TBB-backed
	# Parallel STL the moment /usr/include/tbb/tbb.h is visible on the
	# sysroot include path (bits/c++config.h: "#define
	# _GLIBCXX_USE_TBB_PAR_BACKEND __has_include(<tbb/tbb.h>)", unguarded by
	# anything this project controls). The sniper sysroot ships those
	# headers but nothing here links -ltbb, so any TU that transitively
	# includes <algorithm> (every DKUtil consumer does) compiles clean but
	# fails at LINK time with "undefined reference to
	# tbb::interface7::internal::task_arena_base::internal_current_slot()".
	# This define must land on the compiler command line -- before
	# bits/c++config.h's own header guard resolves it for the whole TU -- so
	# it must be a command-line -D, not something set from inside a DKUtil
	# header (by the time any of our own headers run, an earlier standard
	# include already latched the default). Harmless on a non-sniper build:
	# it only disables an opt-in parallel backend nothing here requests.
	_GLIBCXX_USE_TBB_PAR_BACKEND=0
)

function(add_cave_harness_test name)
	add_executable(${name} src/${name}.cpp $<TARGET_OBJECTS:cave_harness_targets>)
	target_include_directories(${name} PRIVATE ${CAVE_HARNESS_INCLUDES} src)
	target_compile_definitions(${name} PRIVATE ${CAVE_HARNESS_DEFS})
	target_link_libraries(${name} PRIVATE dl pthread)
	add_test(NAME ${name} COMMAND ${name})
endfunction()

enable_testing()

# (1) AddRelHook / write_call<5>
add_cave_harness_test(test_relhook)

# (2) AddASMPatch at a mid-function site
add_cave_harness_test(test_asmpatch)

# (3) AddCaveHook: SysV register/SSE preservation via an Xbyak prolog/epilog
add_cave_harness_test(test_cavehook_regs)

# (3) AddCaveHook: displaced RIP-relative instruction (relocated or rejected?)
add_cave_harness_test(test_cavehook_riprelative)

# (4) Trampoline/Xbyak W^X posture
add_cave_harness_test(test_wx)

# (5) SiteCatalog resolve() / resolve_host() round-trip, guest_exit, and the
#     WARN-and-skip degradation of a malformed row
add_cave_harness_test(test_sitecatalog)

# (6) SiteCatalog gate 1 (build identity). One executable per case, because
#     SiteCatalog is a singleton whose load() runs once per process.
add_cave_harness_test(test_sitecatalog_identity_ok)
add_cave_harness_test(test_sitecatalog_identity_mismatch)
add_cave_harness_test(test_sitecatalog_identity_textsize)
