#include "crypto.hpp"

#include <openssl/sha.h>

#include <array>
#include <cstring>
#include <stdexcept>

namespace {

constexpr std::size_t kKeccakStateWords = 25;
constexpr std::size_t kKeccakRate = 136;  // bytes for SHA3-256

constexpr std::uint64_t rotl64(std::uint64_t x, std::uint64_t y) {
  return (x << y) | (x >> (64 - y));
}

void keccak_f(std::uint64_t *state) {
  static constexpr std::uint64_t kRoundConstants[24] = {
      0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
      0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
      0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
      0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
      0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
      0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
      0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
      0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

  static constexpr std::uint32_t kRhoOffsets[24] = {
      1,  3,  6, 10, 15, 21, 28, 36, 45, 55, 2,  14,
      27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

  static constexpr std::uint32_t kPiLane[24] = {10, 7, 11, 17, 18, 3, 5, 16,
                                                8, 21, 24, 4, 15, 23, 19, 13,
                                                12, 2, 20, 14, 22, 9, 6, 1};

  for (int round = 0; round < 24; ++round) {
    std::uint64_t C[5];
    for (int x = 0; x < 5; ++x) {
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^
             state[x + 20];
    }

    std::uint64_t D[5];
    for (int x = 0; x < 5; ++x) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    }

    for (int i = 0; i < 25; ++i) state[i] ^= D[i % 5];

    std::uint64_t B[25];
    for (int i = 0; i < 25; ++i) B[i] = state[i];

    for (int i = 0; i < 24; ++i) {
      state[kPiLane[i]] = rotl64(B[i + 1], kRhoOffsets[i]);
    }

    for (int y = 0; y < 5; ++y) {
      for (int x = 0; x < 5; ++x) {
        int idx = x + 5 * y;
        int idx1 = ((x + 1) % 5) + 5 * y;
        int idx2 = ((x + 2) % 5) + 5 * y;
        state[idx] = state[idx] ^ ((~state[idx1]) & state[idx2]);
      }
    }

    state[0] ^= kRoundConstants[round];
  }
}

}  // namespace

namespace crypto {

void keccak256(const std::uint8_t *data, std::size_t len,
               std::uint8_t out[32]) {
  std::uint64_t state[kKeccakStateWords]{};
  std::uint8_t temp[kKeccakRate]{};

  std::size_t offset = 0;
  while (len >= kKeccakRate) {
    std::memcpy(temp, data + offset, kKeccakRate);
    for (std::size_t i = 0; i < kKeccakRate / 8; ++i) {
      std::uint64_t lane;
      std::memcpy(&lane, temp + i * 8, 8);
      state[i] ^= lane;
    }
    keccak_f(state);
    offset += kKeccakRate;
    len -= kKeccakRate;
  }

  std::fill(std::begin(temp), std::end(temp), 0);
  if (len > 0) {
    std::memcpy(temp, data + offset, len);
  }
  temp[len] = 0x01;
  temp[kKeccakRate - 1] |= 0x80;

  for (std::size_t i = 0; i < kKeccakRate / 8; ++i) {
    std::uint64_t lane;
    std::memcpy(&lane, temp + i * 8, 8);
    state[i] ^= lane;
  }
  keccak_f(state);

  for (int i = 0; i < 4; ++i) {
    std::uint64_t lane = state[i];
    std::memcpy(out + i * 8, &lane, 8);
  }
}

void sha256(const std::uint8_t *data, std::size_t len, std::uint8_t out[32]) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, len);
  SHA256_Final(out, &ctx);
}

std::string base58_check_encode(const std::uint8_t *payload, std::size_t len) {
  static constexpr char alphabet[] =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::uint8_t checksum_input[64];
  if (len + 4 > sizeof(checksum_input)) {
    throw std::runtime_error("payload too large");
  }

  std::memcpy(checksum_input, payload, len);

  std::uint8_t hash1[32];
  std::uint8_t hash2[32];
  sha256(checksum_input, len, hash1);
  sha256(hash1, sizeof(hash1), hash2);

  std::vector<std::uint8_t> buffer(payload, payload + len);
  buffer.insert(buffer.end(), hash2, hash2 + 4);

  std::size_t zeros = 0;
  while (zeros < buffer.size() && buffer[zeros] == 0) {
    ++zeros;
  }

  std::vector<std::uint8_t> temp(buffer.size() * 138 / 100 + 1);
  std::size_t size = 0;
  for (std::size_t i = zeros; i < buffer.size(); ++i) {
    int carry = buffer[i];
    for (std::size_t j = 0; carry != 0 || j < size; ++j) {
      int value = carry + 256 * temp[j];
      temp[j] = value % 58;
      carry = value / 58;
      if (j + 1 > size) size = j + 1;
    }
  }

  std::string result(zeros, '1');
  for (std::size_t i = 0; i < size; ++i) {
    result.push_back(alphabet[temp[size - 1 - i]]);
  }
  return result;
}

std::string to_hex(const std::uint8_t *data, std::size_t len) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(hex[(data[i] >> 4) & 0xF]);
    out.push_back(hex[data[i] & 0xF]);
  }
  return out;
}

}  // namespace crypto

