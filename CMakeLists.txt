cmake_minimum_required(VERSION 3.20)
project(sift VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(HYPERSCAN REQUIRED IMPORTED_TARGET libhs)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
find_package(nlohmann_json 3.10 REQUIRED)

add_library(sift_core
    src/engine.cpp
    src/sxbn.cpp
)
target_include_directories(sift_core PUBLIC include)
target_link_libraries(sift_core PUBLIC nlohmann_json::nlohmann_json PkgConfig::HYPERSCAN)
target_compile_options(sift_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(sx-siftd
    src/main.cpp
    src/server.cpp
)
target_include_directories(sx-siftd PRIVATE
    external/lmhpp/include
)
target_link_libraries(sx-siftd PRIVATE
    sift_core PkgConfig::MICROHTTPD nlohmann_json::nlohmann_json)
target_compile_options(sx-siftd PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

include(CTest)
if(BUILD_TESTING)
    add_executable(sift_tests tests/engine_tests.cpp)
    target_link_libraries(sift_tests PRIVATE sift_core)
    add_test(NAME sift_tests COMMAND sift_tests)
endif()

install(TARGETS sift_core sx-siftd
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
