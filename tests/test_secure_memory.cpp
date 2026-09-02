#include <catch2/catch_test_macros.hpp>
#include "aegis/common.hpp"
#include <type_traits>
#include <algorithm>

TEST_CASE("Secure memory allocator and vector integration", "[memory][security]") {
    SECTION("Allocator type binding") {
        STATIC_REQUIRE(std::is_same_v<
            aegis::secure_vector::allocator_type, 
            aegis::secure_allocator<uint8_t>
        >);
    }

    SECTION("Direct allocator lifecycle") {
        aegis::secure_allocator<uint8_t> alloc;
        size_t size = 64;

        uint8_t* ptr = alloc.allocate(size);
        REQUIRE(ptr != nullptr);

        std::fill_n(ptr, size, 0xBB);
        REQUIRE(ptr[0] == 0xBB);
        REQUIRE(ptr[size - 1] == 0xBB);

        REQUIRE_NOTHROW(alloc.deallocate(ptr, size));
    }

    SECTION("Secure vector capacity and lifetime management") {
        aegis::secure_vector vec(128, 0xA5);
        REQUIRE(vec.size() == 128);
        REQUIRE(vec[0] == 0xA5);

        vec.resize(256, 0x5A);
        REQUIRE(vec.size() == 256);
        REQUIRE(vec[255] == 0x5A);
    }
}