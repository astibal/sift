#include <sift/engine.hpp>
#include <sift/structure.hpp>

#include "matching.hpp"

#include <algorithm>
#include <cmath>
#include <hs/hs.h>
#include <stdexcept>

#include <compiled_signatures.hpp>

namespace sift {
namespace {

struct ScanContext {
    std::unordered_set<std::size_t>& candidates;
    std::uint64_t emitted{};
};

// Hyperscan only nominates rules; exact clauses remain authoritative.
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

} // namespace

void Runtime::load_signature_pack() {
    // This generated JSON is compiled from the human-maintained YAML policy.
    const auto pack = nlohmann::json::parse(generated::signature_pack);
    for (const auto& source : pack.at("signatures")) {
        Rule rule{source.at("name").get<std::string>(), source.at("match"),
                  source.contains("candidates") && !source.at("candidates").empty()};
        for(const auto& clause : rule.clauses) {
            if(clause.contains("field") || clause.contains("fields")) continue;
            required_evidence_bytes_ = std::max(
                required_evidence_bytes_,
                matching::required_evidence_bytes(clause));
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
    // Clauses are ANDed; aliases within one metadata clause are ORed.
    const auto values = [](const nlohmann::json& clause) {
        std::vector<std::string> result;
        if (clause.contains("values")) result = clause.at("values").get<std::vector<std::string>>();
        else if (clause.contains("value")) result.push_back(clause.at("value").get<std::string>());
        return result;
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

            return std::any_of(field_names.begin(), field_names.end(),
                               [&](const auto& field_name) {
                const auto found = flow.fields.find(field_name);
                if(found == flow.fields.end()) return false;
                return matching::field_matches(op, expected, found->second);
            });
        }
        const auto side_text = clause.value("side", "E");
        const auto side = side_text.empty() ? 'E' : side_text.front();
        if(side == 'L') return matching::stream_matches(clause, flow.left);
        if(side == 'R') return matching::stream_matches(clause, flow.right);
        return matching::stream_matches(clause, flow.left) ||
               matching::stream_matches(clause, flow.right);
    });
}

Runtime::Runtime(RuntimeConfig config) : config_(config) {
    // Build immutable scanner resources before accepting flow data.
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
    // Prefer expiry; if still full, evict the least recently active flow.
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
    // Metadata accumulates across packets but remains bounded per flow.
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
    // Streaming Hyperscan cheaply narrows the exact rules evaluated below.
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

    // Ungated rules run directly; candidate-driven rules run only after their
    // inexpensive scanner pattern has appeared.
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

    // Probe known application-payload ranges without surrounding TLS framing.
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
    matching::append_timing_sample(engine_delay_recent_ns_, elapsed);
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
    matching::append_timing_sample(total_delay_recent_ns_, value);
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
    // Validate a copy so a rejected update cannot partly mutate live limits.
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
    // One lock makes counters and flow state a coherent point-in-time snapshot.
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
                                          {"median", matching::median_microseconds(engine_delay_recent_ns_)},
                                          {"median_samples", engine_delay_recent_ns_.size()},
                                          {"average", average_engine_delay}}},
                    {"total_delay_us", {{"samples", total_delay_samples_},
                                         {"last", ns_to_us(total_delay_last_ns_)},
                                         {"min", total_delay_samples_ == 0 ? 0.0 : ns_to_us(total_delay_min_ns_)},
                                         {"max", ns_to_us(total_delay_max_ns_)},
                                         {"median", matching::median_microseconds(total_delay_recent_ns_)},
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
