#include "matching.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <vector>

namespace sift::matching {
namespace {

constexpr std::size_t timing_median_window = 4096;

std::string normalized_hostname(std::string_view hostname) {
    while(!hostname.empty() && hostname.back() == '.') hostname.remove_suffix(1);

    std::string result;
    result.reserve(hostname.size());
    for(const auto value : hostname) {
        result.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(value))));
    }
    return result;
}

bool domain_is(const std::string_view hostname, const std::string_view domain) {
    return hostname == domain ||
           (hostname.size() > domain.size() && hostname.ends_with(domain) &&
            hostname[hostname.size() - domain.size() - 1] == '.');
}

bool starts_with_ci(const std::string_view stream,
                    const std::string_view prefix) {
    if(stream.size() < prefix.size()) return false;

    return std::equal(
        prefix.begin(), prefix.end(), stream.begin(),
        [](const char left, const char right) {
            return std::tolower(static_cast<unsigned char>(left)) ==
                   std::tolower(static_cast<unsigned char>(right));
        });
}

bool path_has_extension(std::string_view path,
                        const std::string_view extension) {
    path = path.substr(0, path.find_first_of("?#"));
    if(extension.empty() || path.size() <= extension.size()) return false;

    const auto extension_offset = path.size() - extension.size();
    if(extension_offset == 0 || path[extension_offset - 1] != '.') return false;
    return std::equal(
        extension.begin(), extension.end(), path.begin() + extension_offset,
        [](const char left, const char right) {
            return std::tolower(static_cast<unsigned char>(left)) ==
                   std::tolower(static_cast<unsigned char>(right));
        });
}

bool bytes_at(const std::string_view value, const std::size_t offset,
              const std::string_view bytes) {
    return value.size() >= offset + bytes.size() &&
           value.substr(offset, bytes.size()) == bytes;
}

std::optional<std::uint32_t> integer_at(
    const std::string_view stream, const std::size_t offset,
    const std::size_t width, const bool little_endian) {
    if(width == 0 || width > 4 || offset > stream.size() ||
       width > stream.size() - offset) {
        return std::nullopt;
    }

    std::uint32_t value{};
    for(std::size_t index = 0; index < width; ++index) {
        const auto source = little_endian ? width - index - 1U : index;
        value = (value << 8U) |
                static_cast<unsigned char>(stream[offset + source]);
    }
    return value;
}

struct QuicVarint {
    std::uint64_t value{};
    std::size_t end{};
};

// QUIC stores both the integer value and its byte width in the two high bits.
std::optional<QuicVarint> quic_varint_at(
    const std::string_view stream, const std::size_t offset) {
    if(offset >= stream.size()) return std::nullopt;

    const auto first = static_cast<std::uint8_t>(stream[offset]);
    const auto width = std::size_t{1} << (first >> 6U);
    if(width > stream.size() - offset) return std::nullopt;

    std::uint64_t value = first & 0x3fU;
    for(std::size_t index = 1; index < width; ++index) {
        value = (value << 8U) |
                static_cast<std::uint8_t>(stream[offset + index]);
    }
    return QuicVarint{value, offset + width};
}

bool quic_long_header_matches(const std::string_view stream,
                              const nlohmann::json& clause) {
    const auto offset = clause.value("offset", 0U);
    const auto maximum_cid = clause.value("max_connection_id_length", 20U);
    if(offset > stream.size() || stream.size() - offset < 7U) return false;

    std::size_t cursor = static_cast<std::size_t>(offset) + 5U;
    const auto destination_length =
        static_cast<std::uint8_t>(stream[cursor++]);
    if(destination_length > maximum_cid ||
       destination_length > stream.size() - cursor) {
        return false;
    }
    cursor += destination_length;
    if(cursor >= stream.size()) return false;

    const auto source_length = static_cast<std::uint8_t>(stream[cursor++]);
    if(source_length > maximum_cid || source_length > stream.size() - cursor) {
        return false;
    }
    cursor += source_length;

    if(clause.value("has_token_length", false)) {
        const auto token_length = quic_varint_at(stream, cursor);
        if(!token_length.has_value() ||
           token_length->value > stream.size() - token_length->end) {
            return false;
        }
        cursor = token_length->end +
                 static_cast<std::size_t>(token_length->value);
    }

    const auto payload_length = quic_varint_at(stream, cursor);
    if(!payload_length.has_value()) return false;

    const auto packet_number_length =
        (static_cast<std::uint8_t>(stream[offset]) & 0x03U) + 1U;
    return payload_length->value >= packet_number_length &&
           payload_length->value <= stream.size() - payload_length->end;
}

bool has_label_sequence(const std::string_view stream,
                        const std::size_t offset,
                        const std::size_t maximum_label,
                        const std::size_t trailing_bytes) {
    if(offset >= stream.size()) return false;

    auto cursor = offset;
    bool saw_label{};
    while(cursor < stream.size()) {
        const auto length = static_cast<unsigned char>(stream[cursor++]);
        if(length == 0) {
            return saw_label && stream.size() - cursor >= trailing_bytes;
        }
        if(length > maximum_label || length > stream.size() - cursor) {
            return false;
        }

        saw_label = true;
        cursor += length;
    }
    return false;
}

// Minimal BER view for signatures; intentionally not a general ASN.1 decoder.
struct BerElement {
    std::uint8_t tag{};
    std::size_t value_offset{};
    std::size_t end{};
};

std::optional<BerElement> ber_element_at(
    const std::string_view stream, const std::size_t offset) {
    if(offset + 2U > stream.size()) return std::nullopt;

    const auto tag = static_cast<std::uint8_t>(stream[offset]);
    const auto first_length = static_cast<std::uint8_t>(stream[offset + 1U]);
    std::size_t cursor = offset + 2U;
    std::size_t length{};

    if((first_length & 0x80U) == 0) {
        length = first_length;
    } else {
        const auto octets = static_cast<std::size_t>(first_length & 0x7fU);
        if(octets == 0 || octets > 4 || cursor + octets > stream.size()) {
            return std::nullopt;
        }
        if(static_cast<std::uint8_t>(stream[cursor]) == 0) {
            return std::nullopt;
        }

        for(std::size_t index = 0; index < octets; ++index) {
            length = (length << 8U) |
                     static_cast<std::uint8_t>(stream[cursor++]);
        }
        if(length < 128U) return std::nullopt;
    }

    if(length > stream.size() - cursor) return std::nullopt;
    return BerElement{tag, cursor, cursor + length};
}

bool ber_sequence_matches(const std::string_view stream,
                          const nlohmann::json& clause) {
    const auto offset = clause.value("offset", 0U);
    const auto outer = ber_element_at(stream, offset);
    if(!outer.has_value() || outer->tag != clause.value("tag", 0x30U)) {
        return false;
    }
    if(clause.value("exact_frame", true) && outer->end != stream.size()) {
        return false;
    }

    auto cursor = outer->value_offset;
    for(const auto& expected : clause.at("children")) {
        const auto child = ber_element_at(stream, cursor);
        if(!child.has_value() || child->end > outer->end) return false;

        const auto minimum = expected.value(
            "tag_min", expected.value("tag", 0U));
        const auto maximum = expected.value(
            "tag_max", expected.value("tag", 255U));
        if(child->tag < minimum || child->tag > maximum) return false;
        cursor = child->end;
    }

    return clause.value("allow_extra", false) || cursor == outer->end;
}

bool ber_frame_matches(const std::string_view stream,
                       const nlohmann::json& clause) {
    const auto offset = clause.value("offset", 0U);
    const auto element = ber_element_at(stream, offset);
    if(!element.has_value() || element->end != stream.size()) return false;

    if(clause.contains("tags")) {
        const auto tags = clause.at("tags").get<std::vector<std::uint8_t>>();
        return std::find(tags.begin(), tags.end(), element->tag) != tags.end();
    }

    const auto minimum = clause.value(
        "tag_min", clause.value("tag", 0U));
    const auto maximum = clause.value(
        "tag_max", clause.value("tag", 255U));
    return element->tag >= minimum && element->tag <= maximum;
}

bool tls_hello(const std::string_view stream,
               const unsigned char handshake_type) {
    if(stream.size() < 11 || static_cast<unsigned char>(stream[0]) != 0x16 ||
       static_cast<unsigned char>(stream[1]) != 0x03 ||
       (static_cast<unsigned char>(stream[2]) & 0xf0U) != 0 ||
       static_cast<unsigned char>(stream[5]) != handshake_type) {
        return false;
    }

    const auto record_length = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(stream[3]) << 8U) |
        static_cast<unsigned char>(stream[4]));
    const auto handshake_length = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(stream[6]) << 16U) |
        (static_cast<unsigned char>(stream[7]) << 8U) |
        static_cast<unsigned char>(stream[8]));
    return record_length >= 4 && handshake_length + 4U <= record_length;
}

std::vector<std::string> clause_values(const nlohmann::json& clause) {
    if(clause.contains("values")) {
        return clause.at("values").get<std::vector<std::string>>();
    }
    if(clause.contains("value")) {
        return {clause.at("value").get<std::string>()};
    }
    return {};
}

} // namespace

std::string decode_hex(const std::string_view encoded) {
    if(encoded.size() % 2 != 0) return {};

    const auto nibble = [](const char value) -> int {
        if(value >= '0' && value <= '9') return value - '0';
        if(value >= 'a' && value <= 'f') return value - 'a' + 10;
        if(value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };

    std::string result;
    result.reserve(encoded.size() / 2);
    for(std::size_t index = 0; index < encoded.size(); index += 2) {
        const auto high = nibble(encoded[index]);
        const auto low = nibble(encoded[index + 1]);
        if(high < 0 || low < 0) return {};
        result.push_back(static_cast<char>((high << 4) | low));
    }
    return result;
}

std::size_t required_evidence_bytes(const nlohmann::json& clause) {
    // Keep this calculation aligned with stream_matches(): retaining less data
    // would make an otherwise valid exact match impossible.
    const auto operation = clause.at("op").get<std::string>();

    if(operation == "tls_handshake") return 11;
    if(operation == "uint_at" || operation == "size_from_uint_at") {
        return clause.value("offset", 0U) +
               clause.at("width").get<std::size_t>();
    }
    if(operation == "label_sequence_at") {
        return clause.at("offset").get<std::size_t>() + 2U;
    }
    if(operation == "size_between") return clause.value("min", 0U);
    if(operation == "ber_sequence" || operation == "ber_frame") {
        return clause.value("offset", 0U) + 2U;
    }
    if(operation == "quic_long_header") {
        return clause.value("offset", 0U) + 7U;
    }
    if(operation == "candidate_seen") return 0;
    if(operation == "decimal_prefix") {
        return clause.at("digits").get<std::size_t>() + 1U;
    }
    if(operation == "hex_at") {
        return clause.value("offset", 0U) +
               decode_hex(clause.at("value").get<std::string>()).size();
    }

    const auto values = clause_values(clause);
    const auto longest = std::accumulate(
        values.begin(), values.end(), std::size_t{},
        [](const std::size_t current, const std::string& value) {
            return std::max(current, value.size());
        });
    return operation == "line_prefix_within"
        ? clause.value("limit", 0U) + longest + 1U
        : longest;
}

bool stream_matches(const nlohmann::json& clause,
                    const std::string_view stream) {
    const auto operation = clause.at("op").get<std::string>();
    const auto values = clause_values(clause);

    if(operation == "prefix" || operation == "prefix_any") {
        return std::any_of(values.begin(), values.end(),
                           [stream](const auto& value) {
                               return stream.starts_with(value);
                           });
    }
    if(operation == "prefix_any_ci") {
        return std::any_of(values.begin(), values.end(),
                           [stream](const auto& value) {
                               return starts_with_ci(stream, value);
                           });
    }
    if(operation == "decimal_prefix") {
        const auto digits = clause.at("digits").get<std::size_t>();
        const auto separators = clause.at("separators").get<std::string>();
        if(stream.size() <= digits) return false;

        return std::all_of(
                   stream.begin(),
                   stream.begin() + static_cast<std::ptrdiff_t>(digits),
                   [](const char value) {
                       return std::isdigit(
                                  static_cast<unsigned char>(value)) != 0;
                   }) &&
               separators.find(stream[digits]) != std::string::npos;
    }
    if(operation == "hex_at") {
        const auto bytes = decode_hex(values.at(0));
        return !bytes.empty() &&
               bytes_at(stream, clause.value("offset", 0U), bytes);
    }
    if(operation == "tls_handshake") {
        return tls_hello(
            stream,
            static_cast<unsigned char>(clause.at("type").get<unsigned>()));
    }
    if(operation == "uint_at" || operation == "size_from_uint_at") {
        const auto width = clause.at("width").get<std::size_t>();
        const auto offset = clause.value("offset", 0U);
        const auto integer = integer_at(
            stream, offset, width, clause.value("endian", "be") == "le");
        if(!integer.has_value()) return false;

        if(operation == "size_from_uint_at") {
            const auto adjustment = clause.value("adjustment", 0U);
            return static_cast<std::uint64_t>(*integer) + adjustment ==
                   stream.size();
        }

        if(clause.contains("mask") && clause.contains("masked_values")) {
            const auto masked =
                *integer & clause.at("mask").get<std::uint32_t>();
            const auto accepted = clause.at("masked_values")
                                      .get<std::vector<std::uint32_t>>();
            if(std::find(accepted.begin(), accepted.end(), masked) ==
               accepted.end()) {
                return false;
            }
        } else if(clause.contains("mask") &&
                  ((*integer & clause.at("mask").get<std::uint32_t>()) !=
                   clause.value("masked_value", 0U))) {
            return false;
        }
        return *integer >= clause.value("min", 0U) &&
               *integer <= clause.value(
                               "max",
                               std::numeric_limits<std::uint32_t>::max());
    }
    if(operation == "label_sequence_at") {
        return has_label_sequence(
            stream, clause.at("offset").get<std::size_t>(),
            clause.value("max_label", 63U),
            clause.value("trailing_min", 0U));
    }
    if(operation == "size_between") {
        return stream.size() >= clause.value("min", 0U) &&
               stream.size() <= clause.value(
                                    "max",
                                    std::numeric_limits<std::size_t>::max());
    }
    if(operation == "ber_sequence") return ber_sequence_matches(stream, clause);
    if(operation == "ber_frame") return ber_frame_matches(stream, clause);
    if(operation == "quic_long_header") {
        return quic_long_header_matches(stream, clause);
    }
    // Reached only after Hyperscan has selected the owning rule.
    if(operation == "candidate_seen") return true;
    if(operation == "line_prefix_within") {
        const auto position = stream.find(values.at(0));
        return position != std::string_view::npos &&
               position <= clause.value("limit", 0U) &&
               (position == 0 || stream[position - 1] == '\n');
    }

    throw std::runtime_error(
        "unsupported stream signature operation: " + operation);
}

bool field_matches(
    const std::string_view operation,
    const std::vector<std::string>& expected,
    const std::unordered_set<std::string>& observed) {
    if(operation == "equals_any") {
        return std::any_of(
            observed.begin(), observed.end(), [&](const auto& value) {
                return std::find(expected.begin(), expected.end(), value) !=
                       expected.end();
            });
    }
    if(operation == "domain_suffix_any") {
        // Compare complete DNS labels, not arbitrary string suffixes.
        return std::any_of(
            observed.begin(), observed.end(), [&](const auto& hostname) {
                const auto normalized = normalized_hostname(hostname);
                return std::any_of(
                    expected.begin(), expected.end(), [&](const auto& domain) {
                        return domain_is(normalized,
                                         normalized_hostname(domain));
                    });
            });
    }
    if(operation == "path_extension_any") {
        // Query parameters and fragments are not part of a resource's file
        // extension. Comparison is case-insensitive because deployed HTTP
        // paths are not consistently cased even when formats define a usual
        // lowercase suffix.
        return std::any_of(
            observed.begin(), observed.end(), [&](const auto& path) {
                return std::any_of(
                    expected.begin(), expected.end(), [&](const auto& extension) {
                        return path_has_extension(path, extension);
                    });
            });
    }

    throw std::runtime_error(
        "unsupported field signature operation: " + std::string(operation));
}

void append_timing_sample(std::deque<std::uint64_t>& samples,
                          const std::uint64_t value) {
    if(samples.size() == timing_median_window) samples.pop_front();
    samples.push_back(value);
}

double median_microseconds(const std::deque<std::uint64_t>& samples) {
    if(samples.empty()) return 0.0;

    std::vector<std::uint64_t> ordered(samples.begin(), samples.end());
    const auto middle =
        ordered.begin() + static_cast<std::ptrdiff_t>(ordered.size() / 2);
    std::nth_element(ordered.begin(), middle, ordered.end());
    if(ordered.size() % 2 != 0) {
        return static_cast<double>(*middle) / 1000.0;
    }

    const auto lower = *std::max_element(ordered.begin(), middle);
    return (static_cast<double>(lower) + static_cast<double>(*middle)) / 2000.0;
}

} // namespace sift::matching
