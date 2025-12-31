#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

struct Address {
  std::string base58;
  std::array<std::uint8_t, 32> private_key{};
};

void keccak256(const std::uint8_t *data, std::size_t len,
               std::uint8_t out[32]);

void sha256(const std::uint8_t *data, std::size_t len, std::uint8_t out[32]);

std::string base58_check_encode(const std::uint8_t *payload, std::size_t len);

std::string to_hex(const std::uint8_t *data, std::size_t len);

}  // namespace crypto

