#include <sift/engine.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <hs/hs.h>
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

bool domain_is(const std::string_view hostname, const std::string_view domain) {
    return hostname == domain ||
           (hostname.size() > domain.size() && hostname.ends_with(domain) &&
            hostname[hostname.size() - domain.size() - 1] == '.');
}

bool at(const std::string_view value, const std::size_t offset,
        const std::string_view bytes) {
    return value.size() >= offset + bytes.size() && value.substr(offset, bytes.size()) == bytes;
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
        if (op == "hex_at") {
            const auto bytes = decode_hex(candidates.at(0));
            return !bytes.empty() && at(stream, clause.value("offset", 0U), bytes);
        }
        if (op == "tls_handshake") {
            return tls_hello(stream, static_cast<unsigned char>(clause.at("type").get<unsigned>()));
        }
        if (op == "line_prefix_within") {
            const auto position = stream.find(candidates.at(0));
            return position != std::string_view::npos && position <= clause.value("limit", 0U) &&
                   (position == 0 || stream[position - 1] == '\n');
        }
        throw std::runtime_error("unsupported stream signature operation: " + op);
    };

    return std::all_of(rule.clauses.begin(), rule.clauses.end(),
                       [&](const nlohmann::json& clause) {
        const auto side_text = clause.value("side", "E");
        const auto side = side_text.empty() ? 'E' : side_text.front();
        const auto op = clause.at("op").get<std::string>();
        if (side == 'H') {
            if (op != "domain_suffix_any")
                throw std::runtime_error("unsupported hostname signature operation: " + op);
            const auto domains = values(clause);
            return std::any_of(flow.hostnames.begin(), flow.hostnames.end(),
                               [&domains](const auto& hostname) {
                return std::any_of(domains.begin(), domains.end(),
                                   [&hostname](const auto& domain) {
                                       return domain_is(hostname, domain);
                                   });
            });
        }
        if (side == 'L') return stream_matches(clause, flow.left);
        if (side == 'R') return stream_matches(clause, flow.right);
        return stream_matches(clause, flow.left) || stream_matches(clause, flow.right);
    });
}

Runtime::Runtime() {
    try {
        load_signature_pack();
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

Verdict Runtime::inspect(const std::string_view session, const char side,
                         const std::string_view payload,
                         const InspectionMetadata& metadata) {
    const auto engine_started = std::chrono::steady_clock::now();
    std::scoped_lock guard(lock_);
    auto [flow_it, inserted] = flows_.try_emplace(std::string(session));
    if (inserted) ++flows_seen_;
    const auto is_right = side == 'R' || side == 'w';
    auto& flow = flow_it->second;
    for (const auto& hostname : metadata.hostnames) {
        auto normalized = normalized_hostname(hostname);
        if (!normalized.empty()) flow.hostnames.emplace(std::move(normalized));
    }
    auto& stream = is_right ? flow.right : flow.left;
    auto*& scanner = is_right ? flow.right_scanner : flow.left_scanner;
    auto* database = is_right ? right_database_ : left_database_;
    if (scanner == nullptr && hs_open_stream(database, 0, &scanner) != HS_SUCCESS)
        throw std::runtime_error("cannot open Hyperscan stream");
    stream.append(payload);
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
    const auto record_match = [&](const Rule& rule) {
        flow.matches.emplace(rule.name);
        verdict.matches.push_back({rule.name, 0, stream.empty() ? 0 : stream.size() - 1});
        ++matches_;
        ++signature_matches_[rule.name];
    };
    for (const auto& rule : rules_) {
        if (rule.candidate_driven || flow.matches.contains(rule.name)) continue;
        if (rule_matches(rule, flow)) record_match(rule);
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
        record_match(rule);
        candidate = flow.candidates.erase(candidate);
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

void Runtime::close(const std::string_view session) {
    std::scoped_lock guard(lock_);
    const auto found = flows_.find(std::string(session));
    if (found == flows_.end()) return;
    close_scanners(found->second);
    flows_.erase(found);
    ++flows_closed_;
}

nlohmann::json Runtime::status() const {
    std::scoped_lock guard(lock_);
    auto signatures = nlohmann::json::object();
    for (const auto& rule : rules_) {
        const auto found = signature_matches_.find(rule.name);
        signatures[rule.name] = found == signature_matches_.end() ? 0 : found->second;
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
    return {
        {"service", "siftd"}, {"engine", "compiled-yaml-hyperscan"},
        {"scanner", {{"name", "hyperscan"}, {"version", hs_version()},
                     {"mode", "stream"}, {"patterns", scan_patterns_.size()},
                     {"scans", hyperscan_scans_},
                     {"candidates", hyperscan_candidates_}}},
        {"uptime_ms", uptime},
        {"flows", {{"active", flows_.size()}, {"seen", flows_seen_},
                   {"closed", flows_closed_}}},
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
                           {"end", match.end}});
    }
    return {{"action", verdict.action}, {"matches", std::move(matches)},
            {"engine", "siftd"}};
}

} // namespace sift
