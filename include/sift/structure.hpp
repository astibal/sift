#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sift::structure {

struct TlvMatch {
    std::string signature;
    double confidence{};
    std::size_t offset{};
    std::size_t records{};
    std::size_t covered_bytes{};
    bool needs_more{};
};

struct TlvOptions {
    std::size_t max_magic_bytes{32};
    std::size_t max_probe_bytes{64U * 1024U};
    std::size_t max_records{256};
    std::size_t min_records{3};
};

/** Infer a repeated length-framed binary layout without protocol knowledge. */
[[nodiscard]] std::optional<TlvMatch> infer_tlv(
    std::string_view bytes, const TlvOptions& options = {});

/** Return equally plausible layouts instead of hiding structural ambiguity. */
[[nodiscard]] std::vector<TlvMatch> infer_tlv_candidates(
    std::string_view bytes, const TlvOptions& options = {});

} // namespace sift::structure
