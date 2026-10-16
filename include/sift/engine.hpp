#pragma once

#include <cstdint>
#include <chrono>
#include <deque>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>
#include <hs/hs.h>

#include <sift/identity.hpp>

namespace sift {

struct RuntimeConfig {
    std::size_t evidence_bytes_per_side{64U * 1024U};
    std::size_t max_flows{10000};
    std::uint64_t min_idle_ttl_seconds{10U * 60U};
    std::uint64_t max_idle_ttl_seconds{24U * 60U * 60U};
    std::uint64_t tombstone_ttl_seconds{30};
    std::uint64_t sweep_interval_seconds{5};
    std::size_t max_field_names_per_flow{128};
    std::size_t max_values_per_field{64};
    std::size_t max_structure_probes_per_flow{8};
};

struct Match {
    std::string signature;
    std::size_t begin{};
    std::size_t end{};
    char side{};
    std::string payload_layer;
    double confidence{1.0};
};

struct Verdict {
    std::string action{"accept"};
    std::vector<Match> matches;
};

struct InspectionMetadata {
    struct L7PayloadRange {
        std::size_t begin{};
        std::size_t end{};
        std::string encoding;
    };

    std::unordered_map<std::string, std::vector<std::string>> fields;
    std::string payload_layer{"tcp"};
    std::string payload_stream;
    std::vector<L7PayloadRange> l7_payload_ranges;
    bool l7_payload_known{};
};

class Runtime {
public:
    explicit Runtime(RuntimeConfig config = {});
    ~Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    [[nodiscard]] Verdict inspect(const FlowKey& key, char side,
                                  std::string_view payload,
                                  const InspectionMetadata& metadata = {});
    [[nodiscard]] Verdict inspect(std::string_view session, char side,
                                  std::string_view payload,
                                  const InspectionMetadata& metadata = {});
    void start(const FlowKey& key);
    void record_total_delay(std::chrono::nanoseconds elapsed);
    void close(const FlowKey& key);
    void close(std::string_view session);
    [[nodiscard]] nlohmann::json status();
    [[nodiscard]] nlohmann::json config() const;
    bool configure(const nlohmann::json& update, std::string& error);

private:
    struct Rule {
        std::string name;
        nlohmann::json clauses;
        bool candidate_driven{};
    };
    struct ScanPattern {
        std::string expression;
        unsigned rule{};
        char side{'E'};
    };
    struct Flow {
        struct StructureProbe {
            std::string bytes;
            std::size_t next_probe{64};
            bool done{};
        };

        std::string left;
        std::string right;
        std::unordered_set<std::string> matches;
        std::unordered_map<std::string, std::unordered_set<std::string>> fields;
        std::unordered_set<std::size_t> candidates;
        std::unordered_map<std::string, StructureProbe> structure_probes;
        std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
        std::uint64_t left_bytes_seen{};
        std::uint64_t right_bytes_seen{};
        hs_stream_t* left_scanner{};
        hs_stream_t* right_scanner{};
    };

    void close_scanners(Flow& flow);
    void sweep_locked(std::chrono::steady_clock::time_point now, bool force = false);
    void ensure_capacity_locked(std::chrono::steady_clock::time_point now,
                                bool reserve_slot = true);
    [[nodiscard]] std::chrono::seconds current_idle_ttl_locked() const;
    [[nodiscard]] std::size_t active_evidence_bytes_locked() const;
    [[nodiscard]] nlohmann::json config_locked() const;
    void load_signature_pack();
    [[nodiscard]] hs_database_t* compile_database(char side) const;
    [[nodiscard]] bool rule_matches(const Rule& rule, const Flow& flow) const;

    mutable std::mutex lock_;
    std::vector<Rule> rules_;
    std::vector<ScanPattern> scan_patterns_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    std::unordered_map<FlowKey, std::chrono::steady_clock::time_point, FlowKeyHash> tombstones_;
    RuntimeConfig config_;
    std::size_t required_evidence_bytes_{};
    std::chrono::steady_clock::time_point next_sweep_{std::chrono::steady_clock::now()};
    std::unordered_set<std::string> tenants_seen_;
    std::unordered_set<std::string> instances_seen_;
    std::uint64_t ip_fallback_requests_{};
    hs_database_t* left_database_{};
    hs_database_t* right_database_{};
    hs_scratch_t* scratch_{};
    const std::chrono::steady_clock::time_point started_{std::chrono::steady_clock::now()};
    std::unordered_map<std::string, std::uint64_t> signature_matches_;
    std::uint64_t flows_seen_{};
    std::uint64_t flows_closed_{};
    std::uint64_t flows_started_{};
    std::uint64_t flows_expired_{};
    std::uint64_t flows_evicted_{};
    std::uint64_t late_payloads_dropped_{};
    std::uint64_t metadata_fields_dropped_{};
    std::uint64_t metadata_values_dropped_{};
    std::size_t peak_flows_{};
    std::size_t peak_evidence_bytes_{};
    std::uint64_t payloads_{};
    std::uint64_t bytes_{};
    std::uint64_t matches_{};
    std::uint64_t matched_payloads_{};
    std::uint64_t left_payloads_{};
    std::uint64_t left_bytes_{};
    std::uint64_t right_payloads_{};
    std::uint64_t right_bytes_{};
    std::uint64_t accepted_{};
    std::uint64_t hyperscan_scans_{};
    std::uint64_t hyperscan_candidates_{};
    std::uint64_t structure_scans_{};
    std::uint64_t structure_candidates_{};
    std::uint64_t last_payload_size_{};
    std::uint64_t min_payload_size_{std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t max_payload_size_{};
    std::uint64_t engine_delay_samples_{};
    std::uint64_t engine_delay_total_ns_{};
    std::uint64_t engine_delay_last_ns_{};
    std::uint64_t engine_delay_min_ns_{std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t engine_delay_max_ns_{};
    std::deque<std::uint64_t> engine_delay_recent_ns_;
    std::uint64_t total_delay_samples_{};
    std::uint64_t total_delay_total_ns_{};
    std::uint64_t total_delay_last_ns_{};
    std::uint64_t total_delay_min_ns_{std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t total_delay_max_ns_{};
    std::deque<std::uint64_t> total_delay_recent_ns_;
};

[[nodiscard]] nlohmann::json verdict_json(const Verdict& verdict);

} // namespace sift
