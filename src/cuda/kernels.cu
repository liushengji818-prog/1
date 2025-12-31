#include "gpu_runner.hpp"

#include <cuda.h>
#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

__device__ __forceinline__ std::uint64_t rotl64(std::uint64_t x, int n) {
  return (x << n) | (x >> (64 - n));
}

__device__ void keccak_f(std::uint64_t *state) {
  const std::uint64_t kRoundConstants[24] = {
      0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
      0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
      0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
      0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
      0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
      0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
      0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
      0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000000008008ULL};

  const int kRhoOffsets[24] = {1,  3,  6, 10, 15, 21, 28, 36, 45, 55, 2,  14,
                               27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
  const int kPiLane[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                           15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

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
        state[idx] ^= (~state[idx1]) & state[idx2];
      }
    }

    state[0] ^= kRoundConstants[round];
  }
}

__device__ void keccak256(const std::uint8_t *data, std::uint8_t out[32]) {
  constexpr int rate = 136;
  std::uint64_t state[25] = {0};
  std::uint8_t block[rate] = {0};
  for (int i = 0; i < 64; ++i) block[i] = data[i];
  block[64] = 0x01;
  block[rate - 1] |= 0x80;

  // Absorb (pubkey is 64 bytes)
  for (int i = 0; i < rate / 8; ++i) {
    std::uint64_t lane = 0;
    for (int b = 0; b < 8; ++b) {
      lane |= static_cast<std::uint64_t>(block[i * 8 + b]) << (8 * b);
    }
    state[i] ^= lane;
  }
  keccak_f(state);

  for (int i = 0; i < 4; ++i) {
    std::uint64_t lane = state[i];
    for (int b = 0; b < 8; ++b) {
      out[i * 8 + b] = static_cast<std::uint8_t>((lane >> (8 * b)) & 0xFF);
    }
  }
}

__device__ void sha256(const std::uint8_t *data, int len, std::uint8_t out[32]) {
  // Minimal SHA256; reused from a compact implementation specialized for small input.
  auto rotr = [](std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
  const std::uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  std::uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  std::uint8_t padded[64] = {0};
  for (int i = 0; i < len; ++i) padded[i] = data[i];
  padded[len] = 0x80;
  std::uint64_t bitlen = static_cast<std::uint64_t>(len) * 8;
  for (int i = 0; i < 8; ++i) padded[56 + i] = (bitlen >> (56 - 8 * i)) & 0xFF;

  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(padded[4 * i]) << 24) |
           (static_cast<std::uint32_t>(padded[4 * i + 1]) << 16) |
           (static_cast<std::uint32_t>(padded[4 * i + 2]) << 8) |
           (static_cast<std::uint32_t>(padded[4 * i + 3]));
  }
  for (int i = 16; i < 64; ++i) {
    std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
  std::uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

  for (int i = 0; i < 64; ++i) {
    std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    std::uint32_t ch = (e & f) ^ ((~e) & g);
    std::uint32_t temp1 = h + S1 + ch + K[i] + w[i];
    std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    std::uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;
  H[5] += f;
  H[6] += g;
  H[7] += h;

  for (int i = 0; i < 8; ++i) {
    out[4 * i] = (H[i] >> 24) & 0xFF;
    out[4 * i + 1] = (H[i] >> 16) & 0xFF;
    out[4 * i + 2] = (H[i] >> 8) & 0xFF;
    out[4 * i + 3] = H[i] & 0xFF;
  }
}

__device__ int base58_encode(const std::uint8_t *data, int len, char *out) {
  const char *alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::uint8_t buf[64];
  int buf_len = 0;

  int zeros = 0;
  while (zeros < len && data[zeros] == 0) ++zeros;

  for (int i = zeros; i < len; ++i) {
    int carry = data[i];
    for (int j = 0; j < buf_len || carry; ++j) {
      int val = carry + (j < buf_len ? buf[j] : 0) * 256;
      if (j >= buf_len) buf_len = j + 1;
      buf[j] = val % 58;
      carry = val / 58;
    }
  }

  int pos = 0;
  for (int i = 0; i < zeros; ++i) out[pos++] = '1';
  for (int i = 0; i < buf_len; ++i) out[pos + i] = alphabet[buf[buf_len - 1 - i]];
  return pos + buf_len;
}

__global__ void scan_kernel(const std::uint8_t *pubkeys, std::size_t count,
                            const char *suffix, int suffix_len,
                            std::size_t *hits, char *addr_buf,
                            std::size_t max_hits) {
  std::size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx >= count) return;

  const std::uint8_t *pk = pubkeys + idx * 64;
  std::uint8_t hash[32];
  keccak256(pk, hash);

  std::uint8_t payload[21];
  payload[0] = 0x41;
  for (int i = 0; i < 20; ++i) payload[1 + i] = hash[12 + i];

  std::uint8_t checksum_data[21];
  for (int i = 0; i < 21; ++i) checksum_data[i] = payload[i];
  std::uint8_t sha1[32];
  sha256(checksum_data, 21, sha1);
  std::uint8_t sha2[32];
  sha256(sha1, 32, sha2);

  std::uint8_t full[25];
  for (int i = 0; i < 21; ++i) full[i] = payload[i];
  for (int i = 0; i < 4; ++i) full[21 + i] = sha2[i];

  char encoded[64];
  int enc_len = base58_encode(full, 25, encoded);

  bool match = true;
  if (enc_len < suffix_len) match = false;
  if (match) {
    for (int i = 0; i < suffix_len; ++i) {
      if (encoded[enc_len - suffix_len + i] != suffix[i]) {
        match = false;
        break;
      }
    }
  }

  if (match) {
    std::size_t slot = atomicAdd((unsigned long long *)hits, 1ULL);
    if (slot < max_hits) {
      for (int i = 0; i < enc_len; ++i) addr_buf[slot * 64 + i] = encoded[i];
      addr_buf[slot * 64 + enc_len] = '\0';
      hits[slot + 1] = idx;  // store index after the counter
    }
  }
}

}  // namespace

namespace gpu {

MatchGPUResult scan_suffix(const std::uint8_t *pubkeys, std::size_t count,
                           const std::string &suffix, bool force_cpu) {
  if (force_cpu || count == 0) {
    return MatchGPUResult{};
  }

  int device = 0;
  cudaError_t err = cudaGetDevice(&device);
  if (err != cudaSuccess) {
    return MatchGPUResult{};
  }

  std::size_t threads = 256;
  std::size_t blocks = (count + threads - 1) / threads;

  std::uint8_t *d_pubkeys = nullptr;
  std::size_t pub_bytes = count * 64;
  cudaMalloc(&d_pubkeys, pub_bytes);
  cudaMemcpy(d_pubkeys, pubkeys, pub_bytes, cudaMemcpyHostToDevice);

  char *d_suffix = nullptr;
  cudaMalloc(&d_suffix, suffix.size());
  cudaMemcpy(d_suffix, suffix.data(), suffix.size(), cudaMemcpyHostToDevice);

  constexpr std::size_t kMaxHits = 1024;
  std::size_t *d_hits = nullptr;
  cudaMalloc(&d_hits, sizeof(std::size_t) * (kMaxHits + 1));
  cudaMemset(d_hits, 0, sizeof(std::size_t) * (kMaxHits + 1));

  char *d_addr_buf = nullptr;
  cudaMalloc(&d_addr_buf, kMaxHits * 64);

  scan_kernel<<<blocks, threads>>>(d_pubkeys, count, d_suffix,
                                   static_cast<int>(suffix.size()), d_hits,
                                   d_addr_buf, kMaxHits);
  cudaDeviceSynchronize();

  std::vector<std::size_t> h_hits(kMaxHits + 1);
  cudaMemcpy(h_hits.data(), d_hits, sizeof(std::size_t) * (kMaxHits + 1),
             cudaMemcpyDeviceToHost);

  std::size_t total_hits = h_hits[0];
  MatchGPUResult result;
  result.hit_indices.reserve(total_hits);
  result.addresses.reserve(total_hits);

  if (total_hits > 0) {
    std::vector<char> h_addr_buf(kMaxHits * 64);
    cudaMemcpy(h_addr_buf.data(), d_addr_buf, kMaxHits * 64,
               cudaMemcpyDeviceToHost);

    for (std::size_t i = 0; i < total_hits && i < kMaxHits; ++i) {
      std::size_t idx = h_hits[i + 1];
      result.hit_indices.push_back(idx);
      result.addresses.emplace_back(h_addr_buf.data() + i * 64);
    }
  }

  cudaFree(d_pubkeys);
  cudaFree(d_suffix);
  cudaFree(d_hits);
  cudaFree(d_addr_buf);

  return result;
}

}  // namespace gpu
