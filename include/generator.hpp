#pragma once

#include "crypto.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace tron {

struct MatchRequest {
  std::string suffix;
  std::size_t batch_size{1 << 14};
  std::size_t max_iterations{0};
  bool use_gpu{true};
  unsigned int threads{0};
};

struct MatchResult {
  crypto::Address address;
  std::string hex_private_key;
};

class AddressGenerator {
 public:
  AddressGenerator();
  ~AddressGenerator();

  AddressGenerator(const AddressGenerator &) = delete;
  AddressGenerator &operator=(const AddressGenerator &) = delete;

  MatchResult run(const MatchRequest &request,
                  const std::function<void(std::size_t)> &progress_cb =
                      {});

 private:
  struct Keypair {
    std::array<std::uint8_t, 32> priv;
    std::array<std::uint8_t, 65> uncompressed_pub;
  };

  Keypair generate_keypair();
  crypto::Address build_address(const Keypair &kp);
};

}  // namespace tron

