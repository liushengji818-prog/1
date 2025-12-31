#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace gpu {
struct MatchGPUResult {
  std::vector<std::size_t> hit_indices;
  std::vector<std::string> addresses;
};

MatchGPUResult scan_suffix(const std::uint8_t *pubkeys, std::size_t count,
                           const std::string &suffix, bool force_cpu);
}  // namespace gpu

