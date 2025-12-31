#include "gpu_runner.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace gpu {
MatchGPUResult scan_suffix(const std::uint8_t *pubkeys, std::size_t count,
                           const std::string &suffix, bool /*force_cpu*/) {
  // Pure CPU fallback: hashing performed elsewhere; this only reports no hits.
  // The caller will fall back to CPU hashing when GPU support is unavailable.
  return MatchGPUResult{std::vector<std::size_t>{}, std::vector<std::string>{}};
}
}  // namespace gpu

