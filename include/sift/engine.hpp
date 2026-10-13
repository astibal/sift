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
    Runtime();
    ~Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    [[nodiscard]] Verdict inspect(const FlowKey& key, char side,
                                  std::string_view payload,
                                  const InspectionMetadata& metadata = {});
    [[nodiscard]] Verdict inspect(std::string_view session, char side,
                                  std::string_view payload,
                                  const InspectionMetadata& metadata = {});
    void record_total_delay(std::chrono::nanoseconds elapsed);
    void close(const FlowKey& key);
    void close(std::string_view session);
    [[nodiscard]] nlohmann::json status() const;

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
        hs_stream_t* left_scanner{};
        hs_stream_t* right_scanner{};
    };

    void close_scanners(Flow& flow);
    void load_signature_pack();
    [[nodiscard]] hs_database_t* compile_database(char side) const;
    [[nodiscard]] bool rule_matches(const Rule& rule, const Flow& flow) const;

    mutable std::mutex lock_;
    std::vector<Rule> rules_;
    std::vector<ScanPattern> scan_patterns_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
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
