#include <sift/engine.hpp>
#include <sift/structure.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <hs/hs.h>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <vector>

#include <compiled_signatures.hpp>

namespace sift {
namespace {

std::string normalized_hostname(std::string_view hostname) {
    while (!hostname.empty() && hostname.back() == '.') hostname.remove_suffix(1);
    std::string result;
    result.reserve(hostname.size());
    for (const auto ch : hostname) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return result;
}

bool starts_with_ci(const std::string_view stream, const std::string_view prefix) {
    if(stream.size() < prefix.size()) return false;

    return std::equal(
        prefix.begin(), prefix.end(), stream.begin(), [](const char left, const char right) {
            return std::tolower(static_cast<unsigned char>(left)) ==
                   std::tolower(static_cast<unsigned char>(right));
        });
}

bool domain_is(const std::string_view hostname, const std::string_view domain) {
    return hostname == domain ||
           (hostname.size() > domain.size() && hostname.ends_with(domain) &&
            hostname[hostname.size() - domain.size() - 1] == '.');
}

bool at(const std::string_view value, const std::size_t offset,
        const std::string_view bytes) {
    return value.size() >= offset + bytes.size() && value.substr(offset, bytes.size()) == bytes;
}

std::optional<std::uint32_t> integer_at(
    const std::string_view stream, const std::size_t offset,
    const std::size_t width, const bool little_endian) {
    if(width == 0 || width > 4 || offset > stream.size() ||
       width > stream.size() - offset) return std::nullopt;

    std::uint32_t value{};
    for(std::size_t index = 0; index < width; ++index) {
        const auto source = little_endian ? width - index - 1U : index;
        value = (value << 8U) |
            static_cast<unsigned char>(stream[offset + source]);
    }
    return value;
}

bool has_label_sequence(const std::string_view stream, const std::size_t offset,
                        const std::size_t maximum_label,
                        const std::size_t trailing_bytes) {
    if(offset >= stream.size()) return false;

    auto cursor = offset;
    bool saw_label{};
    while(cursor < stream.size()) {
        const auto length = static_cast<unsigned char>(stream[cursor++]);
        if(length == 0) return saw_label && stream.size() - cursor >= trailing_bytes;
        if(length > maximum_label || length > stream.size() - cursor) return false;

        saw_label = true;
        cursor += length;
    }
    return false;
}

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
        if(static_cast<std::uint8_t>(stream[cursor]) == 0) return std::nullopt;

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
    if(!outer.has_value() || outer->tag != clause.value("tag", 0x30U)) return false;
    if(clause.value("exact_frame", true) && outer->end != stream.size()) return false;

    auto cursor = outer->value_offset;
    for(const auto& expected : clause.at("children")) {
        const auto child = ber_element_at(stream, cursor);
        if(!child.has_value() || child->end > outer->end) return false;

        const auto minimum = expected.value("tag_min", expected.value("tag", 0U));
        const auto maximum = expected.value("tag_max", expected.value("tag", 255U));
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

    const auto minimum = clause.value("tag_min", clause.value("tag", 0U));
    const auto maximum = clause.value("tag_max", clause.value("tag", 255U));
    return element->tag >= minimum && element->tag <= maximum;
}

bool tls_hello(const std::string_view stream, const unsigned char handshake_type) {
    if (stream.size() < 11 || static_cast<unsigned char>(stream[0]) != 0x16 ||
        static_cast<unsigned char>(stream[1]) != 0x03 ||
        (static_cast<unsigned char>(stream[2]) & 0xf0U) != 0 ||
        static_cast<unsigned char>(stream[5]) != handshake_type) return false;
    const auto record_length = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(stream[3]) << 8U) |
        static_cast<unsigned char>(stream[4]));
    const auto handshake_length = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(stream[6]) << 16U) |
        (static_cast<unsigned char>(stream[7]) << 8U) |
        static_cast<unsigned char>(stream[8]));
    return record_length >= 4 && handshake_length + 4U <= record_length;
}

std::string decode_hex(const std::string_view encoded) {
    if (encoded.size() % 2 != 0) return {};
    auto nibble = [](const char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    std::string result;
    result.reserve(encoded.size() / 2);
    for (std::size_t i = 0; i < encoded.size(); i += 2) {
        const auto high = nibble(encoded[i]);
        const auto low = nibble(encoded[i + 1]);
        if (high < 0 || low < 0) return {};
        result.push_back(static_cast<char>((high << 4) | low));
    }
    return result;
}

struct ScanContext {
    std::unordered_set<std::size_t>& candidates;
    std::uint64_t emitted{};
};

int record_candidate(const unsigned id, unsigned long long, unsigned long long,
                     unsigned, void* context) {
    auto& scan = *static_cast<ScanContext*>(context);
    if (scan.candidates.emplace(id).second) ++scan.emitted;
    return 0;
}

int discard_candidate(unsigned, unsigned long long, unsigned long long,
                      unsigned, void*) {
    return 0;
}

constexpr std::size_t timing_median_window = 4096;

void append_timing_sample(std::deque<std::uint64_t>& samples, const std::uint64_t value) {
    if (samples.size() == timing_median_window) samples.pop_front();
    samples.push_back(value);
}

double median_us(const std::deque<std::uint64_t>& samples) {
    if (samples.empty()) return 0.0;
    std::vector<std::uint64_t> ordered(samples.begin(), samples.end());
    const auto middle = ordered.begin() + static_cast<std::ptrdiff_t>(ordered.size() / 2);
    std::nth_element(ordered.begin(), middle, ordered.end());
    if (ordered.size() % 2 != 0) return static_cast<double>(*middle) / 1000.0;
    const auto lower = *std::max_element(ordered.begin(), middle);
    return (static_cast<double>(lower) + static_cast<double>(*middle)) / 2000.0;
}

} // namespace

void Runtime::load_signature_pack() {
    const auto pack = nlohmann::json::parse(generated::signature_pack);
    for (const auto& source : pack.at("signatures")) {
        Rule rule{source.at("name").get<std::string>(), source.at("match"),
                  source.contains("candidates") && !source.at("candidates").empty()};
        for(const auto& clause : rule.clauses) {
            if(clause.contains("field") || clause.contains("fields")) continue;

            const auto op = clause.at("op").get<std::string>();
            std::size_t needed{};
            if(op == "tls_handshake") {
                needed = 11;
            } else if(op == "uint_at" || op == "size_from_uint_at") {
                needed = clause.value("offset", 0U) + clause.at("width").get<std::size_t>();
            } else if(op == "label_sequence_at") {
                needed = clause.at("offset").get<std::size_t>() + 2U;
            } else if(op == "size_between") {
                needed = clause.value("min", 0U);
            } else if(op == "ber_sequence" || op == "ber_frame") {
                needed = clause.value("offset", 0U) + 2U;
            } else if(op == "candidate_seen") {
                needed = 0;
            } else if(op == "decimal_prefix") {
                needed = clause.at("digits").get<std::size_t>() + 1U;
            } else if(op == "hex_at") {
                const auto encoded = clause.at("value").get<std::string>();
                needed = clause.value("offset", 0U) + decode_hex(encoded).size();
            } else {
                std::vector<std::string> values;
                if(clause.contains("values")) {
                    values = clause.at("values").get<std::vector<std::string>>();
                } else if(clause.contains("value")) {
                    values.push_back(clause.at("value").get<std::string>());
                }
                const auto longest = std::accumulate(
                    values.begin(), values.end(), std::size_t{},
                    [](const std::size_t current, const std::string& value) {
                        return std::max(current, value.size());
                    });
                needed = op == "line_prefix_within"
                    ? clause.value("limit", 0U) + longest + 1U : longest;
            }
            required_evidence_bytes_ = std::max(required_evidence_bytes_, needed);
        }
        const auto rule_id = static_cast<unsigned>(rules_.size());
        rules_.push_back(std::move(rule));
        if (!source.contains("candidates")) continue;
        for (const auto& candidate : source.at("candidates")) {
            const auto side_text = candidate.value("side", "E");
            scan_patterns_.push_back({candidate.at("regex").get<std::string>(), rule_id,
                                      side_text.empty() ? 'E' : side_text.front()});
        }
    }
}

hs_database_t* Runtime::compile_database(const char side) const {
    std::vector<const char*> expressions;
    std::vector<unsigned> flags;
    std::vector<unsigned> ids;
    for (const auto& pattern : scan_patterns_) {
        if (pattern.side != side && pattern.side != 'E') continue;
        expressions.push_back(pattern.expression.c_str());
        flags.push_back(HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH);
        ids.push_back(pattern.rule);
    }
    hs_database_t* database{};
    hs_compile_error_t* error{};
    const auto result = hs_compile_multi(
        expressions.data(), flags.data(), ids.data(),
        static_cast<unsigned>(expressions.size()), HS_MODE_STREAM, nullptr,
        &database, &error);
    if (result != HS_SUCCESS) {
        const std::string message = error && error->message
            ? error->message : "unknown Hyperscan compile error";
        if (error) hs_free_compile_error(error);
        throw std::runtime_error("cannot compile Hyperscan database: " + message);
    }
    return database;
}

bool Runtime::rule_matches(const Rule& rule, const Flow& flow) const {
    const auto values = [](const nlohmann::json& clause) {
        std::vector<std::string> result;
        if (clause.contains("values")) result = clause.at("values").get<std::vector<std::string>>();
        else if (clause.contains("value")) result.push_back(clause.at("value").get<std::string>());
        return result;
    };
    const auto stream_matches = [&values](const nlohmann::json& clause,
                                          const std::string_view stream) {
        const auto op = clause.at("op").get<std::string>();
        const auto candidates = values(clause);
        if (op == "prefix" || op == "prefix_any") {
            return std::any_of(candidates.begin(), candidates.end(),
                               [stream](const auto& value) { return stream.starts_with(value); });
        }
        if(op == "prefix_any_ci") {
            return std::any_of(candidates.begin(), candidates.end(),
                               [stream](const auto& value) {
                                   return starts_with_ci(stream, value);
                               });
        }
        if(op == "decimal_prefix") {
            const auto digits = clause.at("digits").get<std::size_t>();
            const auto separators = clause.at("separators").get<std::string>();
            if(stream.size() <= digits) return false;

            return std::all_of(
                       stream.begin(), stream.begin() + static_cast<std::ptrdiff_t>(digits),
                       [](const char value) {
                           return std::isdigit(static_cast<unsigned char>(value)) != 0;
                       }) && separators.find(stream[digits]) != std::string::npos;
        }
        if (op == "hex_at") {
            const auto bytes = decode_hex(candidates.at(0));
            return !bytes.empty() && at(stream, clause.value("offset", 0U), bytes);
        }
        if (op == "tls_handshake") {
            return tls_hello(stream, static_cast<unsigned char>(clause.at("type").get<unsigned>()));
        }
        if(op == "uint_at" || op == "size_from_uint_at") {
            const auto width = clause.at("width").get<std::size_t>();
            const auto offset = clause.value("offset", 0U);
            const auto integer = integer_at(
                stream, offset, width, clause.value("endian", "be") == "le");
            if(!integer.has_value()) return false;

            if(op == "size_from_uint_at") {
                const auto adjustment = clause.value("adjustment", 0U);
                return static_cast<std::uint64_t>(*integer) + adjustment == stream.size();
            }

            if(clause.contains("mask") &&
               clause.contains("masked_values")) {
                const auto masked = *integer & clause.at("mask").get<std::uint32_t>();
                const auto accepted = clause.at("masked_values")
                    .get<std::vector<std::uint32_t>>();
                if(std::find(accepted.begin(), accepted.end(), masked) == accepted.end()) {
                    return false;
                }
            } else if(clause.contains("mask") &&
                      ((*integer & clause.at("mask").get<std::uint32_t>()) !=
                       clause.value("masked_value", 0U))) {
                return false;
            }
            return *integer >= clause.value("min", 0U) &&
                   *integer <= clause.value(
                       "max", std::numeric_limits<std::uint32_t>::max());
        }
        if(op == "label_sequence_at") {
            return has_label_sequence(
                stream, clause.at("offset").get<std::size_t>(),
                clause.value("max_label", 63U), clause.value("trailing_min", 0U));
        }
        if(op == "size_between") {
            return stream.size() >= clause.value("min", 0U) &&
                   stream.size() <= clause.value("max", std::numeric_limits<std::size_t>::max());
        }
        if(op == "ber_sequence") return ber_sequence_matches(stream, clause);
        if(op == "ber_frame") return ber_frame_matches(stream, clause);
        // candidate_seen is valid only on candidate-driven rules. Reaching
        // rule_matches therefore proves that Hyperscan emitted the rule ID.
        if(op == "candidate_seen") return true;
        if (op == "line_prefix_within") {
            const auto position = stream.find(candidates.at(0));
            return position != std::string_view::npos && position <= clause.value("limit", 0U) &&
                   (position == 0 || stream[position - 1] == '\n');
        }
        throw std::runtime_error("unsupported stream signature operation: " + op);
    };

    return std::all_of(rule.clauses.begin(), rule.clauses.end(),
                       [&](const nlohmann::json& clause) {
        const auto op = clause.at("op").get<std::string>();
        if(clause.contains("field") || clause.contains("fields")) {
            // `fields` represents aliases for the same observation across
            // protocol versions (for example HTTP Host and :authority). A
            // match in any alias satisfies this single clause.
            std::vector<std::string> field_names;
            if(clause.contains("fields")) {
                field_names = clause.at("fields").get<std::vector<std::string>>();
            } else {
                field_names.push_back(clause.at("field").get<std::string>());
            }

            const auto expected = values(clause);
            if(op != "equals_any" && op != "domain_suffix_any") {
                throw std::runtime_error("unsupported field signature operation: " + op);
            }

            return std::any_of(field_names.begin(), field_names.end(),
                               [&](const auto& field_name) {
                const auto found = flow.fields.find(field_name);
                if(found == flow.fields.end()) return false;

                if(op == "equals_any") {
                    return std::any_of(found->second.begin(), found->second.end(),
                                       [&expected](const auto& observed) {
                        return std::find(expected.begin(), expected.end(), observed) !=
                               expected.end();
                    });
                }

                return std::any_of(found->second.begin(), found->second.end(),
                                   [&expected](const auto& hostname) {
                    return std::any_of(expected.begin(), expected.end(),
                                       [&hostname](const auto& domain) {
                        return domain_is(normalized_hostname(hostname),
                                         normalized_hostname(domain));
                    });
                });
            });
        }
        const auto side_text = clause.value("side", "E");
        const auto side = side_text.empty() ? 'E' : side_text.front();
        if (side == 'L') return stream_matches(clause, flow.left);
        if (side == 'R') return stream_matches(clause, flow.right);
        return stream_matches(clause, flow.left) || stream_matches(clause, flow.right);
    });
}

Runtime::Runtime(RuntimeConfig config) : config_(config) {
    try {
        load_signature_pack();
        config_.evidence_bytes_per_side = std::max(
            config_.evidence_bytes_per_side, required_evidence_bytes_);
        left_database_ = compile_database('L');
        right_database_ = compile_database('R');
        if (hs_alloc_scratch(left_database_, &scratch_) != HS_SUCCESS ||
            hs_alloc_scratch(right_database_, &scratch_) != HS_SUCCESS)
            throw std::runtime_error("cannot allocate Hyperscan scratch space");
    } catch (...) {
        if (scratch_) hs_free_scratch(scratch_);
        if (left_database_) hs_free_database(left_database_);
        if (right_database_) hs_free_database(right_database_);
        throw;
    }
}

std::chrono::seconds Runtime::current_idle_ttl_locked() const {
    if(config_.max_flows == 0) {
        return std::chrono::seconds(config_.min_idle_ttl_seconds);
    }

    const auto utilization = std::min(
        1.0, static_cast<double>(flows_.size()) /
             static_cast<double>(config_.max_flows));
    const auto minimum = static_cast<double>(config_.min_idle_ttl_seconds);
    const auto maximum = static_cast<double>(config_.max_idle_ttl_seconds);
    if(minimum == maximum) {
        return std::chrono::seconds(config_.min_idle_ttl_seconds);
    }

    const auto seconds = maximum * std::pow(minimum / maximum, utilization);
    return std::chrono::seconds(static_cast<std::uint64_t>(seconds));
}

std::size_t Runtime::active_evidence_bytes_locked() const {
    return std::accumulate(
        flows_.begin(), flows_.end(), std::size_t{},
        [](const std::size_t total, const auto& entry) {
            return total + entry.second.left.size() + entry.second.right.size();
        });
}

void Runtime::sweep_locked(const std::chrono::steady_clock::time_point now,
                           const bool force) {
    if(!force && now < next_sweep_) return;

    const auto ttl = current_idle_ttl_locked();
    for(auto flow = flows_.begin(); flow != flows_.end();) {
        if(now - flow->second.last_activity < ttl) {
            ++flow;
            continue;
        }

        close_scanners(flow->second);
        flow = flows_.erase(flow);
        ++flows_expired_;
    }

    for(auto tombstone = tombstones_.begin(); tombstone != tombstones_.end();) {
        if(tombstone->second > now) ++tombstone;
        else tombstone = tombstones_.erase(tombstone);
    }

    next_sweep_ = now + std::chrono::seconds(config_.sweep_interval_seconds);
}

void Runtime::ensure_capacity_locked(const std::chrono::steady_clock::time_point now,
                                     const bool reserve_slot) {
    sweep_locked(now, true);

    const auto target = config_.max_flows - (reserve_slot ? 1U : 0U);
    while(flows_.size() > target && !flows_.empty()) {
        const auto oldest = std::min_element(
            flows_.begin(), flows_.end(), [](const auto& left, const auto& right) {
                return left.second.last_activity < right.second.last_activity;
            });
        close_scanners(oldest->second);
        flows_.erase(oldest);
        ++flows_evicted_;
    }
}

Runtime::~Runtime() {
    std::scoped_lock guard(lock_);
    for (auto& [_, flow] : flows_) close_scanners(flow);
    if (scratch_) hs_free_scratch(scratch_);
    if (left_database_) hs_free_database(left_database_);
    if (right_database_) hs_free_database(right_database_);
}

void Runtime::close_scanners(Flow& flow) {
    if (flow.left_scanner) {
        hs_close_stream(flow.left_scanner, scratch_, discard_candidate, nullptr);
        flow.left_scanner = nullptr;
    }
    if (flow.right_scanner) {
        hs_close_stream(flow.right_scanner, scratch_, discard_candidate, nullptr);
        flow.right_scanner = nullptr;
    }
}

Verdict Runtime::inspect(const FlowKey& key, const char side,
                         const std::string_view payload,
                         const InspectionMetadata& metadata) {
    const auto engine_started = std::chrono::steady_clock::now();
    std::scoped_lock guard(lock_);
    const auto now = std::chrono::steady_clock::now();
    sweep_locked(now);

    if(auto stopped = tombstones_.find(key);
       stopped != tombstones_.end() && stopped->second > now) {
        ++late_payloads_dropped_;
        ++accepted_;
        return {};
    }

    auto flow_it = flows_.find(key);
    bool inserted = false;
    if(flow_it == flows_.end()) {
        ensure_capacity_locked(now);
        std::tie(flow_it, inserted) = flows_.try_emplace(key);
    }

    if(inserted) {
        ++flows_seen_;
        peak_flows_ = std::max(peak_flows_, flows_.size());
    }

    tenants_seen_.insert(key.source.tenant);
    instances_seen_.insert(key.source.tenant + "\n" +
                           (key.source.ip_fallback ? "peer-ip\n" : "declared\n") +
                           key.source.instance);

    if(key.source.ip_fallback) ++ip_fallback_requests_;

    const auto is_right = side == 'R' || side == 'w';
    auto& flow = flow_it->second;
    flow.last_activity = now;
    for (const auto& [field, values] : metadata.fields) {
        if(!flow.fields.contains(field) &&
           flow.fields.size() >= config_.max_field_names_per_flow) {
            ++metadata_fields_dropped_;
            continue;
        }

        auto& stored = flow.fields[field];
        for (const auto& value : values) {
            if(value.empty() || stored.contains(value)) continue;
            if(stored.size() >= config_.max_values_per_field) {
                ++metadata_values_dropped_;
                continue;
            }
            stored.emplace(value);
        }
    }
    auto& stream = is_right ? flow.right : flow.left;
    auto& stream_bytes_seen = is_right ? flow.right_bytes_seen : flow.left_bytes_seen;
    auto*& scanner = is_right ? flow.right_scanner : flow.left_scanner;
    auto* database = is_right ? right_database_ : left_database_;
    if (scanner == nullptr && hs_open_stream(database, 0, &scanner) != HS_SUCCESS)
        throw std::runtime_error("cannot open Hyperscan stream");
    const auto evidence_available = config_.evidence_bytes_per_side - stream.size();
    stream.append(payload.data(), std::min(payload.size(), evidence_available));
    stream_bytes_seen += payload.size();
    peak_evidence_bytes_ = std::max(
        peak_evidence_bytes_, active_evidence_bytes_locked());
    ScanContext scan{flow.candidates};
    if (hs_scan_stream(scanner, payload.data(), static_cast<unsigned>(payload.size()),
                       0, scratch_, record_candidate, &scan) != HS_SUCCESS)
        throw std::runtime_error("Hyperscan stream scan failed");
    ++hyperscan_scans_;
    hyperscan_candidates_ += scan.emitted;
    ++payloads_;
    bytes_ += payload.size();
    last_payload_size_ = payload.size();
    min_payload_size_ = std::min(min_payload_size_, static_cast<std::uint64_t>(payload.size()));
    max_payload_size_ = std::max(max_payload_size_, static_cast<std::uint64_t>(payload.size()));
    if (side == 'R' || side == 'w') {
        ++right_payloads_;
        right_bytes_ += payload.size();
    } else {
        ++left_payloads_;
        left_bytes_ += payload.size();
    }

    Verdict verdict;
    const auto record_match = [&](const std::string& signature,
                                  const std::size_t begin,
                                  const std::size_t end,
                                  const double confidence = 1.0,
                                  const bool remember = true) {
        if(remember) flow.matches.emplace(signature);

        verdict.matches.push_back({
            signature, begin, end, is_right ? 'R' : 'L',
            metadata.payload_layer, confidence});
        ++matches_;
        ++signature_matches_[signature];
    };

    for (const auto& rule : rules_) {
        if (rule.candidate_driven || flow.matches.contains(rule.name)) continue;
        if (rule_matches(rule, flow)) {
            record_match(rule.name, 0, stream_bytes_seen == 0 ? 0 : stream_bytes_seen - 1);
        }
    }

    for (auto candidate = flow.candidates.begin(); candidate != flow.candidates.end();) {
        const auto rule_id = *candidate;
        const auto& rule = rules_.at(rule_id);
        if (flow.matches.contains(rule.name)) {
            candidate = flow.candidates.erase(candidate);
            continue;
        }
        if (!rule_matches(rule, flow)) {
            ++candidate;
            continue;
        }
        record_match(rule.name, 0, stream_bytes_seen == 0 ? 0 : stream_bytes_seen - 1);
        candidate = flow.candidates.erase(candidate);
    }

    const auto inspect_structure = [&](const std::string_view bytes,
                                       const std::string_view structure_layer,
                                       const std::string_view encoding) {
        const auto structure_key = std::string(1, is_right ? 'R' : 'L') + "\n" +
            std::string(structure_layer) + "\n" + metadata.payload_stream + "\n" +
            std::string(encoding);
        auto structure = flow.structure_probes.find(structure_key);

        if(structure == flow.structure_probes.end() &&
           flow.structure_probes.size() < config_.max_structure_probes_per_flow) {
            structure = flow.structure_probes.emplace(
                structure_key, Flow::StructureProbe{}).first;
        }
        if(structure == flow.structure_probes.end() || structure->second.done) return;

        auto& probe = structure->second;
        constexpr std::size_t max_probe_bytes = 64U * 1024U;
        const auto available = max_probe_bytes - probe.bytes.size();
        probe.bytes.append(bytes.data(), std::min(bytes.size(), available));

        if(probe.bytes.size() >= probe.next_probe) {
            ++structure_scans_;
            const auto inferred = structure::infer_tlv_candidates(probe.bytes);

            if(!inferred.empty()) {
                structure_candidates_ += inferred.size();

                probe.done = true;
            } else if(probe.next_probe >= max_probe_bytes) {
                probe.done = true;
            } else {
                probe.next_probe = std::min(
                    max_probe_bytes, probe.bytes.size() + 1);
            }
        }
    };

    if(metadata.l7_payload_known) {
        std::unordered_map<std::string, std::string> l7_bytes;

        for(const auto& range : metadata.l7_payload_ranges) {
            if(range.begin > payload.size() || range.end > payload.size()) continue;

            l7_bytes[range.encoding].append(
                payload.data() + range.begin, range.end - range.begin);
        }

        auto l7_layer = std::string{"l7.payload"};
        if(metadata.fields.contains("flow.http3")) l7_layer = "http3.payload";
        else if(metadata.fields.contains("flow.http2")) l7_layer = "http2.payload";
        else if(metadata.fields.contains("flow.http1")) l7_layer = "http1.payload";

        for(const auto& [encoding, bytes] : l7_bytes) {
            if(!encoding.empty()) continue;

            inspect_structure(bytes, l7_layer, encoding);
        }
    } else {
        const auto layer = metadata.payload_layer.empty()
            ? std::string_view{"tcp"} : std::string_view{metadata.payload_layer};
        inspect_structure(payload, layer, {});
    }

    if (!verdict.matches.empty()) ++matched_payloads_;
    ++accepted_;
    const auto elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - engine_started).count());
    ++engine_delay_samples_;
    engine_delay_total_ns_ += elapsed;
    engine_delay_last_ns_ = elapsed;
    engine_delay_min_ns_ = std::min(engine_delay_min_ns_, elapsed);
    engine_delay_max_ns_ = std::max(engine_delay_max_ns_, elapsed);
    append_timing_sample(engine_delay_recent_ns_, elapsed);
    return verdict;
}

Verdict Runtime::inspect(const std::string_view session, const char side,
                         const std::string_view payload,
                         const InspectionMetadata& metadata) {
    return inspect(FlowKey{{"default", "local", false}, std::string(session)},
                   side, payload, metadata);
}

void Runtime::start(const FlowKey& key) {
    std::scoped_lock guard(lock_);
    const auto now = std::chrono::steady_clock::now();
    sweep_locked(now);
    ++flows_started_;

    if(auto stopped = tombstones_.find(key);
       stopped != tombstones_.end() && stopped->second > now) return;

    auto flow = flows_.find(key);
    if(flow == flows_.end()) {
        ensure_capacity_locked(now);
        flow = flows_.try_emplace(key).first;
        ++flows_seen_;
        peak_flows_ = std::max(peak_flows_, flows_.size());
    }

    flow->second.last_activity = now;
}

void Runtime::record_total_delay(const std::chrono::nanoseconds elapsed) {
    const auto value = static_cast<std::uint64_t>(elapsed.count());
    std::scoped_lock guard(lock_);
    ++total_delay_samples_;
    total_delay_total_ns_ += value;
    total_delay_last_ns_ = value;
    total_delay_min_ns_ = std::min(total_delay_min_ns_, value);
    total_delay_max_ns_ = std::max(total_delay_max_ns_, value);
    append_timing_sample(total_delay_recent_ns_, value);
}

void Runtime::close(const FlowKey& key) {
    std::scoped_lock guard(lock_);
    const auto now = std::chrono::steady_clock::now();
    sweep_locked(now);
    const auto found = flows_.find(key);

    if(found != flows_.end()) {
        close_scanners(found->second);
        flows_.erase(found);
        ++flows_closed_;
    }

    tombstones_[key] = now + std::chrono::seconds(config_.tombstone_ttl_seconds);
    const auto tombstone_limit = config_.max_flows * 2U;
    while(tombstones_.size() > tombstone_limit && !tombstones_.empty()) {
        const auto oldest = std::min_element(
            tombstones_.begin(), tombstones_.end(),
            [](const auto& left, const auto& right) {
                return left.second < right.second;
            });
        tombstones_.erase(oldest);
    }
}

void Runtime::close(const std::string_view session) {
    close(FlowKey{{"default", "local", false}, std::string(session)});
}

nlohmann::json Runtime::config_locked() const {
    return {
        {"evidence_bytes_per_side", config_.evidence_bytes_per_side},
        {"required_evidence_bytes", required_evidence_bytes_},
        {"max_flows", config_.max_flows},
        {"min_idle_ttl_seconds", config_.min_idle_ttl_seconds},
        {"max_idle_ttl_seconds", config_.max_idle_ttl_seconds},
        {"current_idle_ttl_seconds", current_idle_ttl_locked().count()},
        {"tombstone_ttl_seconds", config_.tombstone_ttl_seconds},
        {"sweep_interval_seconds", config_.sweep_interval_seconds},
        {"max_field_names_per_flow", config_.max_field_names_per_flow},
        {"max_values_per_field", config_.max_values_per_field},
        {"max_structure_probes_per_flow", config_.max_structure_probes_per_flow}
    };
}

nlohmann::json Runtime::config() const {
    std::scoped_lock guard(lock_);
    return config_locked();
}

bool Runtime::configure(const nlohmann::json& update, std::string& error) {
    if(!update.is_object()) {
        error = "configuration must be a JSON object";
        return false;
    }

    std::scoped_lock guard(lock_);
    auto next = config_;
    const auto read_size = [&](const char* name, std::size_t& target,
                               const std::size_t minimum,
                               const std::size_t maximum) {
        const auto value = update.find(name);
        if(value == update.end()) return true;
        if(!value->is_number_unsigned() &&
           (!value->is_number_integer() || value->get<std::int64_t>() < 0)) {
            error = std::string(name) + " must be an unsigned integer";
            return false;
        }

        const auto parsed = value->get<std::uint64_t>();
        if(parsed < minimum || parsed > maximum) {
            error = std::string(name) + " is outside the allowed range";
            return false;
        }
        target = static_cast<std::size_t>(parsed);
        return true;
    };
    const auto read_seconds = [&](const char* name, std::uint64_t& target,
                                  const std::uint64_t minimum,
                                  const std::uint64_t maximum) {
        const auto value = update.find(name);
        if(value == update.end()) return true;
        if(!value->is_number_unsigned() &&
           (!value->is_number_integer() || value->get<std::int64_t>() < 0)) {
            error = std::string(name) + " must be an unsigned integer";
            return false;
        }

        const auto parsed = value->get<std::uint64_t>();
        if(parsed < minimum || parsed > maximum) {
            error = std::string(name) + " is outside the allowed range";
            return false;
        }
        target = parsed;
        return true;
    };

    static const std::unordered_set<std::string> known{
        "evidence_bytes_per_side", "max_flows", "min_idle_ttl_seconds",
        "max_idle_ttl_seconds", "tombstone_ttl_seconds", "sweep_interval_seconds",
        "max_field_names_per_flow", "max_values_per_field",
        "max_structure_probes_per_flow"};
    for(auto item = update.begin(); item != update.end(); ++item) {
        if(!known.contains(item.key())) {
            error = "unknown configuration field: " + item.key();
            return false;
        }
    }

    if(!read_size("evidence_bytes_per_side", next.evidence_bytes_per_side,
                  required_evidence_bytes_, 16U * 1024U * 1024U) ||
       !read_size("max_flows", next.max_flows, 1, 1000000) ||
       !read_seconds("min_idle_ttl_seconds", next.min_idle_ttl_seconds, 10, 86400) ||
       !read_seconds("max_idle_ttl_seconds", next.max_idle_ttl_seconds, 10, 604800) ||
       !read_seconds("tombstone_ttl_seconds", next.tombstone_ttl_seconds, 1, 3600) ||
       !read_seconds("sweep_interval_seconds", next.sweep_interval_seconds, 1, 300) ||
       !read_size("max_field_names_per_flow", next.max_field_names_per_flow, 1, 4096) ||
       !read_size("max_values_per_field", next.max_values_per_field, 1, 4096) ||
       !read_size("max_structure_probes_per_flow",
                  next.max_structure_probes_per_flow, 1, 4096)) return false;

    if(next.min_idle_ttl_seconds > next.max_idle_ttl_seconds) {
        error = "min_idle_ttl_seconds must not exceed max_idle_ttl_seconds";
        return false;
    }

    config_ = next;
    for(auto& [_, flow] : flows_) {
        flow.left.resize(std::min(flow.left.size(), config_.evidence_bytes_per_side));
        flow.right.resize(std::min(flow.right.size(), config_.evidence_bytes_per_side));
        while(flow.structure_probes.size() > config_.max_structure_probes_per_flow) {
            flow.structure_probes.erase(flow.structure_probes.begin());
        }
    }
    ensure_capacity_locked(std::chrono::steady_clock::now(), false);
    next_sweep_ = std::chrono::steady_clock::now();
    return true;
}

nlohmann::json Runtime::status() {
    std::scoped_lock guard(lock_);
    sweep_locked(std::chrono::steady_clock::now());
    auto signatures = nlohmann::json::object();
    for (const auto& rule : rules_) {
        const auto found = signature_matches_.find(rule.name);
        signatures[rule.name] = found == signature_matches_.end() ? 0 : found->second;
    }

    for(const auto& [name, count] : signature_matches_) {
        if(!signatures.contains(name)) signatures[name] = count;
    }
    const auto uptime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_).count();
    const auto average_payload = payloads_ == 0 ? 0.0
        : static_cast<double>(bytes_) / static_cast<double>(payloads_);
    const auto ns_to_us = [](const std::uint64_t value) {
        return static_cast<double>(value) / 1000.0;
    };
    const auto average_engine_delay = engine_delay_samples_ == 0 ? 0.0
        : ns_to_us(engine_delay_total_ns_) / static_cast<double>(engine_delay_samples_);
    const auto average_total_delay = total_delay_samples_ == 0 ? 0.0
        : ns_to_us(total_delay_total_ns_) / static_cast<double>(total_delay_samples_);
    const auto active_evidence = active_evidence_bytes_locked();
    const auto utilization = config_.max_flows == 0 ? 0.0
        : static_cast<double>(flows_.size()) / static_cast<double>(config_.max_flows);
    return {
        {"service", "siftd"}, {"engine", "compiled-yaml-hyperscan"},
        {"scanner", {{"name", "hyperscan"}, {"version", hs_version()},
                     {"mode", "stream"}, {"patterns", scan_patterns_.size()},
                     {"scans", hyperscan_scans_},
                     {"candidates", hyperscan_candidates_}}},
        {"structure", {{"scanner", "length-framing-inference"},
                       {"scans", structure_scans_},
                       {"candidates", structure_candidates_},
                       {"published", 0},
                       {"status", "experimental-observation-only"}}},
        {"uptime_ms", uptime},
        {"identity", {{"tenants_seen", tenants_seen_.size()},
                      {"instances_seen", instances_seen_.size()},
                      {"ip_fallback_requests", ip_fallback_requests_}}},
        {"flows", {{"active", flows_.size()}, {"seen", flows_seen_},
                   {"started", flows_started_}, {"closed", flows_closed_},
                   {"expired", flows_expired_}, {"evicted", flows_evicted_},
                   {"peak", peak_flows_}, {"capacity", config_.max_flows},
                   {"utilization", utilization},
                   {"idle_ttl_seconds", current_idle_ttl_locked().count()},
                   {"tombstones", tombstones_.size()},
                   {"late_payloads_dropped", late_payloads_dropped_}}},
        {"memory", {{"evidence_bytes", active_evidence},
                    {"peak_evidence_bytes", peak_evidence_bytes_},
                    {"evidence_limit_per_side", config_.evidence_bytes_per_side},
                    {"required_evidence_bytes", required_evidence_bytes_}}},
        {"limits", {{"metadata_fields_dropped", metadata_fields_dropped_},
                    {"metadata_values_dropped", metadata_values_dropped_}}},
        {"config", config_locked()},
        {"traffic", {{"payloads", payloads_}, {"bytes", bytes_},
                     {"sides", {{"L", {{"payloads", left_payloads_}, {"bytes", left_bytes_}}},
                                {"R", {{"payloads", right_payloads_}, {"bytes", right_bytes_}}}}}}},
        {"payload_size_bytes", {{"last", last_payload_size_},
                                {"min", payloads_ == 0 ? 0 : min_payload_size_},
                                {"max", max_payload_size_}, {"average", average_payload}}},
        {"signatures", {{"loaded", rules_.size()},
                        {"matches", matches_}, {"matched_payloads", matched_payloads_},
                        {"by_name", std::move(signatures)}}},
        {"decisions", {{"accept", accepted_}, {"replace", 0}, {"discard", 0}}},
        {"timing", {{"engine_delay_us", {{"samples", engine_delay_samples_},
                                          {"last", ns_to_us(engine_delay_last_ns_)},
                                          {"min", engine_delay_samples_ == 0 ? 0.0 : ns_to_us(engine_delay_min_ns_)},
                                          {"max", ns_to_us(engine_delay_max_ns_)},
                                          {"median", median_us(engine_delay_recent_ns_)},
                                          {"median_samples", engine_delay_recent_ns_.size()},
                                          {"average", average_engine_delay}}},
                    {"total_delay_us", {{"samples", total_delay_samples_},
                                         {"last", ns_to_us(total_delay_last_ns_)},
                                         {"min", total_delay_samples_ == 0 ? 0.0 : ns_to_us(total_delay_min_ns_)},
                                         {"max", ns_to_us(total_delay_max_ns_)},
                                         {"median", median_us(total_delay_recent_ns_)},
                                         {"median_samples", total_delay_recent_ns_.size()},
                                         {"average", average_total_delay}}},
                    {"round_trip_us", nullptr},
                    {"round_trip_status", "requires Smithproxy/broker telemetry"}}}
    };
}

nlohmann::json verdict_json(const Verdict& verdict) {
    auto matches = nlohmann::json::array();
    for (const auto& match : verdict.matches) {
        matches.push_back({{"signature", match.signature}, {"begin", match.begin},
                           {"end", match.end}, {"side", std::string(1, match.side)},
                           {"payload_layer", match.payload_layer},
                           {"confidence", match.confidence}});
    }
    return {{"action", verdict.action}, {"matches", std::move(matches)},
            {"engine", "siftd"}};
}

} // namespace sift
