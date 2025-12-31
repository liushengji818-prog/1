#include "generator.hpp"

#include <chrono>
#include <iostream>
#include <string>

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "用法: " << argv[0] << " <目标后缀> [批次大小] [线程数]\n";
    return 1;
  }

  tron::MatchRequest req{};
  req.suffix = argv[1];
  if (argc >= 3) req.batch_size = std::stoul(argv[2]);
  if (argc >= 4) req.threads = static_cast<unsigned int>(std::stoul(argv[3]));

  tron::AddressGenerator gen;
  auto start = std::chrono::steady_clock::now();
  auto result = gen.run(req, [&](std::size_t iter) {
    if (iter % (req.batch_size * 10) == 0) {
      double secs = std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - start)
                        .count();
      double mkeys = iter / 1e6 / secs;
      std::cerr << "进度: " << iter << " 个密钥 速度: " << mkeys
                << " Mkeys/s\r";
    }
  });

  auto end = std::chrono::steady_clock::now();
  double secs = std::chrono::duration<double>(end - start).count();

  std::cout << "找到匹配地址: " << result.address.base58 << "\n";
  std::cout << "私钥(hex): " << result.hex_private_key << "\n";
  std::cout << "总耗时: " << secs << " 秒\n";
  return 0;
}

