cmake_minimum_required(VERSION 3.20)
project(sift VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(HYPERSCAN REQUIRED IMPORTED_TARGET libhs)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
find_package(nlohmann_json 3.10 REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import yaml"
    RESULT_VARIABLE SIFT_PYYAML_RESULT
    ERROR_QUIET
)
if(NOT SIFT_PYYAML_RESULT EQUAL 0)
    message(FATAL_ERROR "PyYAML is required to compile the Sift signature pack")
endif()

set(SIFT_COMPILED_SIGNATURES ${CMAKE_CURRENT_BINARY_DIR}/generated/compiled_signatures.hpp)
add_custom_command(
    OUTPUT ${SIFT_COMPILED_SIGNATURES}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/compile_signatures.py
            ${CMAKE_CURRENT_SOURCE_DIR}/signatures/default.yaml ${SIFT_COMPILED_SIGNATURES}
    DEPENDS tools/compile_signatures.py signatures/default.yaml
    VERBATIM
)
add_custom_target(sift_signature_pack DEPENDS ${SIFT_COMPILED_SIGNATURES})

add_library(sift_core
    ${SIFT_COMPILED_SIGNATURES}
    src/engine.cpp
    src/identity.cpp
    src/structure.cpp
    src/sxbn.cpp
)
add_dependencies(sift_core sift_signature_pack)
target_include_directories(sift_core PUBLIC include PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(sift_core PUBLIC nlohmann_json::nlohmann_json PkgConfig::HYPERSCAN)
target_compile_options(sift_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(siftd
    src/main.cpp
    src/server.cpp
)
target_include_directories(siftd SYSTEM PRIVATE
    external/lmhpp/include
)
target_link_libraries(siftd PRIVATE
    sift_core PkgConfig::MICROHTTPD nlohmann_json::nlohmann_json)
target_compile_options(siftd PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

include(CTest)
if(BUILD_TESTING)
    add_executable(sift_tests tests/engine_tests.cpp)
    target_link_libraries(sift_tests PRIVATE sift_core)
    add_test(NAME sift_tests COMMAND sift_tests)
    add_test(NAME sift_server_tests
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/server_tests.py
            $<TARGET_FILE:siftd>)
    add_test(NAME sift_incubator_validate
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/validate_incubator.py
            ${CMAKE_CURRENT_SOURCE_DIR}/signatures/incubator/core.yaml
            ${CMAKE_CURRENT_SOURCE_DIR}/signatures/incubator/protocols-extra.yaml
            ${CMAKE_CURRENT_SOURCE_DIR}/signatures/incubator/services.yaml
            ${CMAKE_CURRENT_SOURCE_DIR}/signatures/incubator/content.yaml)
endif()

install(TARGETS sift_core siftd
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY signatures/ DESTINATION share/sift/signatures)
