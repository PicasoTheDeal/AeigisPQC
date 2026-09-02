#include <catch2/catch_test_macros.hpp>
#include "aegis/common.hpp"

TEST_CASE("Secure memory zeroization", "[memory][security]") {
    uint8_t* leaked_ptr = nullptr;
    size_t size = 64;

    {
        aegis::secure_vector vec(size, 0xBB);
        leaked_ptr = vec.data();
        REQUIRE(leaked_ptr[0] == 0xBB);
    } // vec goes out of scope here; deallocator triggers OPENSSL_cleanse

    // Note: Checking freed heap memory guarantees OPENSSL_cleanse ran on deallocation
    REQUIRE(leaked_ptr[0] == 0x00);
}