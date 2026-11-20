# Builds libyara (BSD-3-Clause, GPL-compatible) from source as a static library.
# libyara ships an autotools build only, so the equivalent configuration is reproduced here.
set(TD_YARA_VERSION "v4.5.2")
set(TD_YARA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara" CACHE PATH "libyara source checkout")

if(NOT EXISTS "${TD_YARA_DIR}/libyara/libyara.c")
    find_package(Git REQUIRED)
    message(STATUS "Fetching libyara ${TD_YARA_VERSION} into ${TD_YARA_DIR}")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} clone --depth 1 --branch ${TD_YARA_VERSION}
                https://github.com/VirusTotal/yara.git "${TD_YARA_DIR}"
        RESULT_VARIABLE TD_YARA_CLONE_RESULT)
    if(NOT TD_YARA_CLONE_RESULT EQUAL 0)
        message(FATAL_ERROR
            "libyara sources are missing. Run scripts/fetch_third_party.sh once while online, "
            "or place a libyara ${TD_YARA_VERSION} checkout at ${TD_YARA_DIR}.")
    endif()
endif()

set(Y "${TD_YARA_DIR}/libyara")
file(GLOB TD_YARA_SOURCES
    "${Y}/*.c"
    "${Y}/tlshc/*.c"
    "${Y}/modules/tests/*.c"
    "${Y}/modules/pe/*.c"
    "${Y}/modules/elf/*.c"
    "${Y}/modules/math/*.c"
    "${Y}/modules/time/*.c"
    "${Y}/modules/console/*.c"
    "${Y}/modules/string/*.c"
    "${Y}/modules/dotnet/*.c"
    "${Y}/modules/macho/*.c"
    "${Y}/modules/dex/*.c")

if(APPLE)
    list(APPEND TD_YARA_SOURCES "${Y}/proc/mach.c")
    set(TD_YARA_PROC USE_MACH_PROC)
else()
    list(APPEND TD_YARA_SOURCES "${Y}/proc/linux.c")
    set(TD_YARA_PROC USE_LINUX_PROC)
endif()

add_library(yara_static STATIC ${TD_YARA_SOURCES})
target_include_directories(yara_static
    PUBLIC "${Y}/include"
    PRIVATE "${Y}" "${Y}/modules")
target_compile_definitions(yara_static PRIVATE
    _GNU_SOURCE
    NDEBUG
    ${TD_YARA_PROC}
    HAVE_SCAN_PROC_IMPL=1
    HAVE_STDBOOL_H=1
    HAVE_CLOCK_GETTIME=1
    HAVE_MEMMEM=1
    HAVE_STRLCPY=1
    HAVE_STRLCAT=1
    HAVE_TIMEGM=1
    BUCKETS_128=1
    CHECKSUM_1B=1
    DOTNET_MODULE
    MACHO_MODULE
    DEX_MODULE)
target_compile_options(yara_static PRIVATE -w -fvisibility=hidden)
find_library(TD_LIBM m)
if(TD_LIBM)
    target_link_libraries(yara_static PUBLIC ${TD_LIBM})
endif()
