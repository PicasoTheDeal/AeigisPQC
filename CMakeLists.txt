cmake_minimum_required(VERSION 3.20)
project(aegispqc CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIB oqs REQUIRED)

include_directories(include)

add_library(aegispqc_core
    src/crypto/hybrid_kem.cpp
    src/crypto/mldsa_signer.cpp
    src/crypto/aead.cpp
    src/policy/policy_manager.cpp
    src/session/aegis_session.cpp
    src/net/frame.cpp
    src/c_api.cpp
)

target_link_libraries(aegispqc_core PUBLIC OpenSSL::Crypto ${OQS_LIB})

add_executable(aegis_demo src/main.cpp)
target_link_libraries(aegis_demo PRIVATE aegispqc_core)

# --- Unit Tests Setup ---
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.5.2
)
FetchContent_MakeAvailable(Catch2)

enable_testing()

add_executable(aegis_tests
    tests/test_crypto.cpp
    tests/test_session.cpp
    tests/test_secure_memory.cpp
    tests/test_aead.cpp
    tests/test_c_api.cpp
)

target_link_libraries(aegis_tests PRIVATE aegispqc_core Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(aegis_tests)

# --- Benchmark Executable ---
add_executable(aegis_bench benchmarks/bench_crypto.cpp)
target_link_libraries(aegis_bench PRIVATE aegispqc_core)