#include "generator.hpp"

#include "crypto.hpp"
#include "gpu_runner.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <random>
#include <stdexcept>
#include <thread>

namespace tron {

namespace {

class Secp256k1Context {
 public:
  Secp256k1Context() {
    group_ = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group_) {
      throw std::runtime_error("Failed to create secp256k1 group");
    }
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    order_ = BN_new();
    EC_GROUP_get_order(group_, order_, ctx);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }

  ~Secp256k1Context() {
    BN_free(order_);
    EC_GROUP_free(group_);
  }

  EC_GROUP *group() const { return group_; }
  const BIGNUM *order() const { return order_; }

 private:
  EC_GROUP *group_{nullptr};
  BIGNUM *order_{nullptr};
};

Secp256k1Context &Context() {
  static Secp256k1Context ctx;
  return ctx;
}

std::array<std::uint8_t, 32> random_private(const BIGNUM *order) {
  std::array<std::uint8_t, 32> out{};
  BIGNUM *k = BN_new();
  BN_CTX *bn_ctx = BN_CTX_new();

  do {
    RAND_bytes(out.data(), out.size());
    BN_bin2bn(out.data(), out.size(), k);
  } while (BN_is_zero(k) || BN_cmp(k, order) >= 0);

  BN_clear_free(k);
  BN_CTX_free(bn_ctx);
  return out;
}

std::array<std::uint8_t, 65> derive_uncompressed(const std::array<std::uint8_t, 32> &priv,
                                                 EC_GROUP *group) {
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);

  BIGNUM *bn_priv = BN_bin2bn(priv.data(), priv.size(), nullptr);
  EC_POINT *pub = EC_POINT_new(group);
  EC_POINT_mul(group, pub, bn_priv, nullptr, nullptr, ctx);

  std::array<std::uint8_t, 65> out{};
  std::uint8_t *p = out.data();
  int len = i2o_ECPublicKey(group, pub, nullptr);
  if (len != 65) {
    BN_clear_free(bn_priv);
    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    throw std::runtime_error("Unexpected public key size");
  }
  i2o_ECPublicKey(group, pub, &p);

  BN_clear_free(bn_priv);
  EC_POINT_free(pub);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return out;
}

}  // namespace

AddressGenerator::AddressGenerator() = default;
AddressGenerator::~AddressGenerator() = default;

AddressGenerator::Keypair AddressGenerator::generate_keypair() {
  auto &ctx = Context();
  Keypair kp;
  kp.priv = random_private(ctx.order());
  kp.uncompressed_pub = derive_uncompressed(kp.priv, ctx.group());
  return kp;
}

crypto::Address AddressGenerator::build_address(const Keypair &kp) {
  std::uint8_t hash[32];
  crypto::keccak256(kp.uncompressed_pub.data() + 1, 64, hash);

  std::uint8_t payload[21];
  payload[0] = 0x41;
  std::memcpy(payload + 1, hash + 12, 20);

  crypto::Address addr;
  addr.base58 = crypto::base58_check_encode(payload, sizeof(payload));
  addr.private_key = kp.priv;
  return addr;
}

MatchResult AddressGenerator::run(
    const MatchRequest &request,
    const std::function<void(std::size_t)> &progress_cb) {
  if (request.suffix.empty()) {
    throw std::invalid_argument("Suffix must not be empty");
  }

  const unsigned int thread_count =
      request.threads == 0 ? std::thread::hardware_concurrency()
                           : request.threads;
  const std::size_t batch_size = std::max<std::size_t>(1024, request.batch_size);

  std::atomic<bool> found = false;
  std::atomic<std::size_t> iterations = 0;
  MatchResult result{};

  auto worker = [&](unsigned int /*id*/) {
    std::vector<Keypair> batch;
    batch.reserve(batch_size);

    while (!found.load(std::memory_order_relaxed)) {
      batch.clear();
      for (std::size_t i = 0; i < batch_size; ++i) {
        batch.push_back(generate_keypair());
      }

      if (request.use_gpu) {
        std::vector<std::uint8_t> pub_buffer;
        pub_buffer.reserve(batch.size() * 64);
        for (const auto &kp : batch) {
          pub_buffer.insert(pub_buffer.end(), kp.uncompressed_pub.begin() + 1,
                            kp.uncompressed_pub.end());
        }
        auto gpu_result =
            gpu::scan_suffix(pub_buffer.data(), batch.size(), request.suffix,
                             /*force_cpu=*/false);
        for (std::size_t idx = 0; idx < gpu_result.hit_indices.size(); ++idx) {
          const std::size_t hit = gpu_result.hit_indices[idx];
          if (hit < batch.size()) {
            crypto::Address addr = build_address(batch[hit]);
            if (addr.base58.ends_with(request.suffix)) {
              result.address = addr;
              result.hex_private_key = crypto::to_hex(
                  batch[hit].priv.data(), batch[hit].priv.size());
              found.store(true, std::memory_order_relaxed);
              return;
            }
          }
        }
      }

      // CPU fallback or additional verification
      for (std::size_t i = 0; i < batch.size() && !found.load(); ++i) {
        auto addr = build_address(batch[i]);
        if (addr.base58.ends_with(request.suffix)) {
          result.address = addr;
          result.hex_private_key =
              crypto::to_hex(batch[i].priv.data(), batch[i].priv.size());
          found.store(true, std::memory_order_relaxed);
          break;
        }
      }

      auto total = iterations.fetch_add(batch.size(), std::memory_order_relaxed) +
                   batch.size();
      if (progress_cb) progress_cb(total);

      if (request.max_iterations != 0 &&
          total >= request.max_iterations && !found.load()) {
        throw std::runtime_error("Max iterations reached without match");
      }
    }
  };

  std::vector<std::thread> threads;
  for (unsigned int i = 0; i < thread_count; ++i) {
    threads.emplace_back(worker, i);
  }

  for (auto &t : threads) {
    t.join();
  }

  return result;
}

}  // namespace tron

