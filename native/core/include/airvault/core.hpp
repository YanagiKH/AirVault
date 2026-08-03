#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace airvault {
constexpr std::size_t kMaximumFramePayload = 1024U * 1024U;
constexpr std::uint8_t kFrameVersion = 1;

class CoreError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Frame {
    std::array<std::byte, 16> transfer_id{};
    std::uint32_t stream_index{};
    std::uint64_t chunk_index{};
    bool final_chunk{};
    std::vector<std::byte> payload;
};

[[nodiscard]] std::array<std::byte, 32> sha256_file(const std::filesystem::path& path);
[[nodiscard]] std::string hex_encode(std::span<const std::byte> bytes);
[[nodiscard]] bool constant_time_equal(std::span<const std::byte> left, std::span<const std::byte> right) noexcept;
void secure_zero(std::span<std::byte> bytes) noexcept;
[[nodiscard]] bool is_safe_relative_path(std::string path);
[[nodiscard]] std::vector<std::byte> encode_frame(const Frame& frame);
[[nodiscard]] Frame decode_frame(std::span<const std::byte> encoded);
}  // namespace airvault
