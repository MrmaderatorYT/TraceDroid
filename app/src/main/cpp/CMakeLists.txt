# TraceDroid native forensic core.
# Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
cmake_minimum_required(VERSION 3.22.1)
project(TraceDroid LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(TD_WITH_YARA "Build and link the bundled libyara" ON)

add_library(tdcore STATIC
    common/Util.cpp
    evtx/EvtxMmapReader.cpp
    evtx/BinXmlDecoder.cpp
    evtx/SysmonNormalizer.cpp
    store/EventStore.cpp
    sigma/YamlParser.cpp
    sigma/SigmaRuleCompiler.cpp
    sigma/ConditionAstEvaluator.cpp
    sigma/SigmaEngine.cpp
    graph/ProcessTreeBuilder.cpp
    graph/GraphLayoutEngine.cpp
    yara/YaraEngineWrapper.cpp
    core/ForensicSession.cpp)

target_include_directories(tdcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(tdcore PRIVATE -Wall -Wextra -Wno-unused-parameter -fexceptions -frtti)

if(TD_WITH_YARA)
    include(cmake/yara.cmake)
    target_link_libraries(tdcore PUBLIC yara_static)
    target_compile_definitions(tdcore PUBLIC TD_HAVE_YARA=1)
endif()

find_package(Threads REQUIRED)
target_link_libraries(tdcore PUBLIC Threads::Threads)

if(ANDROID)
    add_library(TraceDroid SHARED jni/JniBridge.cpp)
    target_compile_options(TraceDroid PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_link_libraries(TraceDroid PRIVATE tdcore log)
    target_link_options(TraceDroid PRIVATE -Wl,--gc-sections -Wl,--exclude-libs,ALL)
else()
    # Host build: self-test binary used during development (cmake -S app/src/main/cpp -B build-host).
    add_executable(td_selftest tests/selftest.cpp)
    target_link_libraries(td_selftest PRIVATE tdcore)
endif()
