#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include <sift/engine.hpp>

namespace sift {

enum class LoredMode { disabled, optional, required };

struct LoredConfig {
    std::string url;
    LoredMode mode{LoredMode::disabled};
    std::uint32_t timeout_ms{50};
    std::size_t max_queries_per_flow{5};
    std::size_t max_cache_entries{4096};
    std::uint32_t cache_ttl_seconds{300};
};

class LoredClient {
public:
    explicit LoredClient(LoredConfig config);

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] bool required() const noexcept;
    [[nodiscard]] nlohmann::json enrich(
        const FlowKey& key, const InspectionMetadata& metadata, const Verdict& verdict,
        bool& attempted, bool& succeeded);
    void close(const FlowKey& key);
    [[nodiscard]] nlohmann::json status() const;

private:
    [[nodiscard]] nlohmann::json build_query(
        const InspectionMetadata& metadata, const Verdict& verdict) const;
    void sweep_cache_locked(std::chrono::steady_clock::time_point now);

    struct FlowState {
        InspectionMetadata metadata;
        Verdict verdict;
        std::unordered_set<std::string> fingerprints;
        std::size_t queries{};
        bool resolved{};
        nlohmann::json last_reply;
        std::string last_error;
    };

    struct CacheEntry {
        nlohmann::json reply;
        std::chrono::steady_clock::time_point expires;
    };

    LoredConfig config_;
    mutable std::mutex lock_;
    std::uint64_t requests_{};
    std::uint64_t matched_{};
    std::uint64_t unknown_{};
    std::uint64_t failures_{};
    std::uint64_t skipped_{};
    std::uint64_t flow_cache_hits_{};
    std::uint64_t shared_cache_hits_{};
    std::uint64_t resolved_suppressed_{};
    std::uint64_t limit_suppressed_{};
    std::uint64_t latency_total_us_{};
    std::uint64_t latency_last_us_{};
    std::uint64_t latency_max_us_{};
    std::string last_error_;
    std::unordered_map<FlowKey, std::shared_ptr<FlowState>, FlowKeyHash> flows_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::deque<std::string> cache_order_;
};

[[nodiscard]] std::string_view lored_mode_name(LoredMode mode) noexcept;

} // namespace sift
