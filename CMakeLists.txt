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
    src/policy/policy_manager.cpp
    src/session/aegis_session.cpp
)

target_link_libraries(aegispqc_core PUBLIC OpenSSL::Crypto ${OQS_LIB})

add_executable(aegis_demo src/main.cpp)
target_link_libraries(aegis_demo PRIVATE aegispqc_core)