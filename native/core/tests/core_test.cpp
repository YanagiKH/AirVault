#include "airvault/core.hpp"
#include <array>
#include <cassert>
#include <cstddef>
#include <iostream>

int main() {
    assert(airvault::is_safe_relative_path("photos/holiday.jpg"));
    assert(!airvault::is_safe_relative_path("../private.txt"));
    assert(!airvault::is_safe_relative_path("C:\\Windows\\system.ini"));
    assert(!airvault::is_safe_relative_path("folder/CON.txt"));
    assert(!airvault::is_safe_relative_path("/etc/passwd"));
    airvault::Frame original;
    original.transfer_id[0] = std::byte{0x42};
    original.stream_index = 7;
    original.chunk_index = 99;
    original.final_chunk = true;
    original.payload = {std::byte{'A'}, std::byte{'V'}};
    const auto encoded = airvault::encode_frame(original);
    const auto decoded = airvault::decode_frame(encoded);
    assert(decoded.transfer_id == original.transfer_id);
    assert(decoded.stream_index == original.stream_index);
    assert(decoded.chunk_index == original.chunk_index);
    assert(decoded.final_chunk == original.final_chunk);
    assert(decoded.payload == original.payload);
    auto malformed = encoded;
    malformed[39] = std::byte{0xff};
    bool rejected = false;
    try { static_cast<void>(airvault::decode_frame(malformed)); } catch (const airvault::CoreError&) { rejected = true; }
    assert(rejected);
    std::array<std::byte, 4> secret{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    assert(airvault::constant_time_equal(secret, secret));
    auto different = secret;
    different[3] = std::byte{5};
    assert(!airvault::constant_time_equal(secret, different));
    airvault::secure_zero(secret);
    assert((secret == std::array<std::byte, 4>{}));
    std::cout << "AirVault native core tests passed\n";
    return 0;
}
