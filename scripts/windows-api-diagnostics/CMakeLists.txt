cmake_minimum_required(VERSION 3.20)
project(ForeverSocketDiagnostics LANGUAGES C CXX)

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "These diagnostics require x64 Windows and MSVC.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Use a static MinHook library" FORCE)
include(FetchContent)
FetchContent_Declare(minhook
  GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
  GIT_TAG c3fcafdc10146beb5919319d0683e44e3c30d537
)
FetchContent_MakeAvailable(minhook)

set(FOREVER_DIAGNOSTIC_REVISION "local" CACHE STRING "Diagnostic source revision")
add_library(ForeverSocketTrace SHARED trace_dll.cpp)
target_link_libraries(ForeverSocketTrace PRIVATE minhook ws2_32)
add_executable(ForeverApiDiagnostics trace_host.cpp)
set_target_properties(ForeverApiDiagnostics PROPERTIES OUTPUT_NAME "Forever-API-Diagnose")
target_link_libraries(ForeverApiDiagnostics PRIVATE ws2_32 version shell32 ole32 advapi32 bcrypt)
foreach(target ForeverSocketTrace ForeverApiDiagnostics)
  target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    FOREVER_DIAGNOSTIC_REVISION="${FOREVER_DIAGNOSTIC_REVISION}")
  target_compile_options(${target} PRIVATE /W4 /EHsc /permissive- /utf-8)
endforeach()

# Redistribute the exact dependency notice alongside the native helper binaries.
configure_file("${minhook_SOURCE_DIR}/LICENSE.txt" "MinHook-LICENSE.txt" COPYONLY)
