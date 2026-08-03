#include "airvault/core.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>

namespace airvault {
namespace {
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

void append_u32(std::vector<std::byte>& output, const std::uint32_t value) {
    output.push_back(static_cast<std::byte>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::byte>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::byte>(value & 0xffU));
}

void append_u64(std::vector<std::byte>& output, const std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) output.push_back(static_cast<std::byte>((value >> static_cast<unsigned>(shift)) & 0xffU));
}

std::uint32_t read_u32(const std::span<const std::byte> bytes, const std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) throw CoreError("truncated uint32");
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) value = (value << 8U) | std::to_integer<std::uint8_t>(bytes[offset + i]);
    return value;
}

std::uint64_t read_u64(const std::span<const std::byte> bytes, const std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 8U) throw CoreError("truncated uint64");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8U; ++i) value = (value << 8U) | std::to_integer<std::uint8_t>(bytes[offset + i]);
    return value;
}

bool is_reserved_windows_name(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char item) { return static_cast<char>(std::tolower(item)); });
    const auto dot = value.find('.');
    if (dot != std::string::npos) value.resize(dot);
    if (value == "con" || value == "prn" || value == "aux" || value == "nul") return true;
    return value.size() == 4U && (value.starts_with("com") || value.starts_with("lpt"))
        && value[3] >= '1' && value[3] <= '9';
}
}  // namespace

std::array<std::byte, 32> sha256_file(const std::filesystem::path& path) {
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(path, status_error);
    if (status_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
        throw CoreError("input is not a regular non-symlink file");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw CoreError("file could not be opened");
    DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) throw CoreError("SHA-256 initialization failed");
    std::array<char, 256U * 1024U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0 && EVP_DigestUpdate(context.get(), buffer.data(), static_cast<std::size_t>(count)) != 1) {
            throw CoreError("SHA-256 update failed");
        }
    }
    if (!input.eof()) throw CoreError("file read failed");
    std::array<std::byte, 32> digest{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context.get(), reinterpret_cast<unsigned char*>(digest.data()), &length) != 1 || length != digest.size()) {
        throw CoreError("SHA-256 finalization failed");
    }
    return digest;
}

std::string hex_encode(const std::span<const std::byte> bytes) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2U);
    for (const auto value : bytes) {
        const auto item = std::to_integer<unsigned char>(value);
        output.push_back(alphabet[item >> 4U]);
        output.push_back(alphabet[item & 0x0fU]);
    }
    return output;
}

bool constant_time_equal(const std::span<const std::byte> left, const std::span<const std::byte> right) noexcept {
    if (left.size() != right.size()) return false;
    if (left.empty()) return true;
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

void secure_zero(const std::span<std::byte> bytes) noexcept {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
}

bool is_safe_relative_path(std::string path) {
    if (path.empty() || path.size() > 4096U || path.front() == '/' || path.front() == '\\') return false;
    if (path.size() >= 2U && std::isalpha(static_cast<unsigned char>(path[0])) != 0 && path[1] == ':') return false;
    if (path.find('\0') != std::string::npos) return false;
    std::replace(path.begin(), path.end(), '\\', '/');
    std::istringstream stream(path);
    std::string component;
    while (std::getline(stream, component, '/')) {
        if (component.empty() || component == "." || component == ".." || component.back() == ' ' || component.back() == '.') return false;
        if (is_reserved_windows_name(component)) return false;
        for (const unsigned char item : component) {
            if (item < 0x20U || item == 0x7fU || item == '<' || item == '>' || item == ':' || item == '"'
                || item == '|' || item == '?' || item == '*') return false;
        }
    }
    return !path.ends_with('/');
}

std::vector<std::byte> encode_frame(const Frame& frame) {
    if (frame.payload.size() > kMaximumFramePayload || frame.payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw CoreError("frame payload exceeds limit");
    }
    std::vector<std::byte> output;
    output.reserve(40U + frame.payload.size());
    output.insert(output.end(), {std::byte{'A'}, std::byte{'V'}, std::byte{'F'}, std::byte{'1'}});
    output.push_back(static_cast<std::byte>(kFrameVersion));
    output.push_back(frame.final_chunk ? std::byte{1} : std::byte{0});
    output.push_back(std::byte{0});
    output.push_back(std::byte{0});
    output.insert(output.end(), frame.transfer_id.begin(), frame.transfer_id.end());
    append_u32(output, frame.stream_index);
    append_u64(output, frame.chunk_index);
    append_u32(output, static_cast<std::uint32_t>(frame.payload.size()));
    output.insert(output.end(), frame.payload.begin(), frame.payload.end());
    return output;
}

Frame decode_frame(const std::span<const std::byte> encoded) {
    constexpr std::size_t header_size = 40U;
    if (encoded.size() < header_size) throw CoreError("frame is truncated");
    if (encoded[0] != std::byte{'A'} || encoded[1] != std::byte{'V'} || encoded[2] != std::byte{'F'} || encoded[3] != std::byte{'1'}) {
        throw CoreError("frame magic is invalid");
    }
    if (encoded[4] != static_cast<std::byte>(kFrameVersion) || (encoded[5] != std::byte{0} && encoded[5] != std::byte{1})
        || encoded[6] != std::byte{0} || encoded[7] != std::byte{0}) throw CoreError("frame header is unsupported");
    const auto length = read_u32(encoded, 36U);
    if (length > kMaximumFramePayload || encoded.size() - header_size != length) throw CoreError("frame length is invalid");
    Frame frame;
    std::copy_n(encoded.begin() + 8, 16, frame.transfer_id.begin());
    frame.stream_index = read_u32(encoded, 24U);
    frame.chunk_index = read_u64(encoded, 28U);
    frame.final_chunk = encoded[5] == std::byte{1};
    frame.payload.assign(encoded.begin() + static_cast<std::ptrdiff_t>(header_size), encoded.end());
    return frame;
}
}  // namespace airvault
