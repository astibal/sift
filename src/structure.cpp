#include <sift/structure.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <sstream>
#include <unordered_set>

namespace sift::structure {
namespace {

enum class ByteOrder { little, big };
enum class LengthMode { value, record };

struct Layout {
    std::size_t offset{};
    std::size_t field_width{};
    std::size_t field_count{};
    std::size_t length_width{};
    ByteOrder order{};
    LengthMode length_mode{};
};

struct Evaluation {
    Layout layout;
    double score{};
    std::size_t records{};
    std::size_t covered_bytes{};
    std::size_t small_fields{};
    std::size_t fields{};
    bool exact{};
    bool needs_more{};
};

std::optional<std::uint64_t> load_integer(const std::string_view bytes,
                                          const std::size_t offset,
                                          const std::size_t width,
                                          const ByteOrder order) {
    if(width == 0 || width > sizeof(std::uint64_t) ||
       offset > bytes.size() || width > bytes.size() - offset) return std::nullopt;

    std::uint64_t result{};

    if(order == ByteOrder::big) {
        for(std::size_t index = 0; index < width; ++index) {
            result = (result << 8U) |
                static_cast<unsigned char>(bytes[offset + index]);
        }
    } else {
        for(std::size_t index = 0; index < width; ++index) {
            result |= static_cast<std::uint64_t>(
                static_cast<unsigned char>(bytes[offset + index])) << (index * 8U);
        }
    }

    return result;
}

std::string signature(const Layout& layout) {
    std::ostringstream result;
    result << "protocol.struct.tlv." << layout.offset << 'm';

    for(std::size_t field = 0; field < layout.field_count; ++field) {
        result << '.' << layout.field_width << 'x';
    }

    result << '.' << layout.length_width << 'l';

    if(layout.length_width > 1) {
        result << (layout.order == ByteOrder::little ? ".le" : ".be");
    }

    result << (layout.length_mode == LengthMode::value ? ".lv" : ".lr");
    return result.str();
}

std::optional<Evaluation> evaluate(const std::string_view bytes,
                                   const Layout& layout,
                                   const TlvOptions& options) {
    const auto fields_size = layout.field_width * layout.field_count;
    const auto header_size = fields_size + layout.length_width;

    if(header_size == 0 || layout.offset >= bytes.size()) return std::nullopt;

    std::size_t cursor = layout.offset;
    Evaluation result{layout};

    while(result.records < options.max_records) {
        const auto remaining = bytes.size() - cursor;

        if(remaining < header_size) {
            result.needs_more = remaining != 0;
            break;
        }

        for(std::size_t field = 0; field < layout.field_count; ++field) {
            const auto value = load_integer(
                bytes, cursor + field * layout.field_width,
                layout.field_width, layout.order);

            if(!value) return std::nullopt;

            ++result.fields;
            if(*value <= 4096U) ++result.small_fields;
        }

        const auto length = load_integer(
            bytes, cursor + fields_size, layout.length_width, layout.order);

        if(!length || *length > options.max_probe_bytes) return std::nullopt;

        std::uint64_t record_size = *length;
        if(layout.length_mode == LengthMode::value) {
            record_size += header_size;
        } else if(record_size < header_size) {
            return std::nullopt;
        }

        if(record_size == 0 || record_size > std::numeric_limits<std::size_t>::max()) {
            return std::nullopt;
        }

        if(record_size > remaining) {
            result.needs_more = true;
            break;
        }

        cursor += static_cast<std::size_t>(record_size);
        ++result.records;

        if(cursor == bytes.size()) {
            result.exact = true;
            break;
        }
    }

    if(result.records < options.min_records) return std::nullopt;

    result.covered_bytes = cursor - layout.offset;
    const auto available = bytes.size() - layout.offset;
    const auto coverage = available == 0 ? 0.0
        : static_cast<double>(result.covered_bytes) / static_cast<double>(available);
    const auto small_ratio = result.fields == 0 ? 0.5
        : static_cast<double>(result.small_fields) / static_cast<double>(result.fields);

    result.score = std::min(35.0, static_cast<double>(result.records) * 7.0) +
                   (result.exact ? 30.0 : 10.0) +
                   20.0 * coverage +
                   15.0 * small_ratio -
                   std::min(8.0, static_cast<double>(layout.offset) * 0.25);

    if(result.records == options.max_records && !result.exact) result.score -= 10.0;
    if(result.needs_more && coverage < 0.5) result.score -= 15.0;

    return result;
}

bool better(const Evaluation& candidate, const Evaluation& current) {
    constexpr double epsilon = 0.001;

    if(candidate.score > current.score + epsilon) return true;
    if(current.score > candidate.score + epsilon) return false;
    if(candidate.exact != current.exact) return candidate.exact;
    if(candidate.records != current.records) return candidate.records > current.records;
    if(candidate.layout.offset != current.layout.offset) {
        return candidate.layout.offset < current.layout.offset;
    }

    return candidate.layout.field_count > current.layout.field_count;
}

} // namespace

std::vector<TlvMatch> infer_tlv_candidates(std::string_view bytes,
                                           const TlvOptions& options) {
    if(bytes.empty() || options.min_records < 2) return {};

    if(bytes.size() > options.max_probe_bytes) {
        bytes = bytes.substr(0, options.max_probe_bytes);
    }

    constexpr std::array<std::size_t, 3> widths{1, 2, 4};
    constexpr std::array<ByteOrder, 2> orders{ByteOrder::little, ByteOrder::big};
    constexpr std::array<LengthMode, 2> modes{LengthMode::value, LengthMode::record};
    std::vector<Evaluation> matches;
    const auto max_offset = std::min(options.max_magic_bytes, bytes.size() - 1);

    for(std::size_t offset = 0; offset <= max_offset; ++offset) {
        for(const auto field_width : widths) {
            for(std::size_t field_count = 0; field_count <= 3; ++field_count) {
                for(const auto length_width : widths) {
                    for(const auto order : orders) {
                        if(length_width == 1 && order == ByteOrder::big) continue;

                        for(const auto mode : modes) {
                            const Layout layout{
                                offset, field_width, field_count,
                                length_width, order, mode};
                            const auto candidate = evaluate(bytes, layout, options);

                            if(candidate && candidate->exact &&
                               candidate->score >= 70.0) {
                                matches.push_back(*candidate);
                            }
                        }
                    }
                }
            }
        }
    }

    if(matches.empty()) return {};

    std::sort(matches.begin(), matches.end(),
              [](const Evaluation& left, const Evaluation& right) {
                  return better(left, right);
              });

    const auto minimum_score = matches.front().score - 3.0;
    std::unordered_set<std::string> emitted;
    std::vector<TlvMatch> result;

    for(const auto& match : matches) {
        if(match.score < minimum_score || result.size() == 8) break;

        auto name = signature(match.layout);
        if(!emitted.emplace(name).second) continue;

        result.push_back({
            std::move(name),
            std::clamp(match.score / 100.0, 0.0, 1.0),
            match.layout.offset,
            match.records,
            match.covered_bytes,
            match.needs_more});
    }

    return result;
}

std::optional<TlvMatch> infer_tlv(std::string_view bytes,
                                  const TlvOptions& options) {
    auto candidates = infer_tlv_candidates(bytes, options);

    if(candidates.empty()) return std::nullopt;

    return std::move(candidates.front());
}

} // namespace sift::structure
