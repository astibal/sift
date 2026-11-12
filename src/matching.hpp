#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace sift::matching {

/** Strictly decode an even-length hexadecimal string; throw on malformed input. */
[[nodiscard]] std::string decode_hex(std::string_view encoded);
/** Return the minimum retained prefix needed to evaluate one exact clause. */
[[nodiscard]] std::size_t required_evidence_bytes(const nlohmann::json& clause);
/** Evaluate a byte-oriented clause against accumulated flow evidence. */
[[nodiscard]] bool stream_matches(const nlohmann::json& clause,
                                  std::string_view stream);
/** Evaluate one metadata-field operation against all observed values. */
[[nodiscard]] bool field_matches(
    std::string_view operation, const std::vector<std::string>& expected,
    const std::unordered_set<std::string>& observed);

/** Append to the bounded diagnostic latency window. */
void append_timing_sample(std::deque<std::uint64_t>& samples,
                          std::uint64_t value);
/** Compute the window median and convert stored nanoseconds to microseconds. */
[[nodiscard]] double median_microseconds(
    const std::deque<std::uint64_t>& samples);

} // namespace sift::matching
