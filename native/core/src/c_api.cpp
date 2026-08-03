#include "airvault/c_api.h"
#include "airvault/core.hpp"

#include <algorithm>
#include <filesystem>
#include <span>

extern "C" {
int airvault_safe_relative_path(const char* path) {
    if (path == nullptr) return 0;
    try { return airvault::is_safe_relative_path(path) ? 1 : 0; } catch (...) { return 0; }
}
int airvault_constant_time_equal(const uint8_t* left, const uint8_t* right, const size_t length) {
    if ((left == nullptr || right == nullptr) && length != 0U) return 0;
    return airvault::constant_time_equal(
        std::span(reinterpret_cast<const std::byte*>(left), length),
        std::span(reinterpret_cast<const std::byte*>(right), length)) ? 1 : 0;
}
void airvault_secure_zero(uint8_t* data, const size_t length) {
    if (data == nullptr && length != 0U) return;
    airvault::secure_zero(std::span(reinterpret_cast<std::byte*>(data), length));
}
int airvault_sha256_file(const char* path, uint8_t output[32]) {
    if (path == nullptr || output == nullptr) return -1;
    try {
        const auto digest = airvault::sha256_file(std::filesystem::path(path));
        std::copy(digest.begin(), digest.end(), reinterpret_cast<std::byte*>(output));
        return 0;
    } catch (...) { return -1; }
}
}
