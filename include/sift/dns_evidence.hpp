#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include <sift/identity.hpp>

namespace sift {

class DnsEvidenceCache {
public:
    bool observe(const SourceIdentity& source, const nlohmann::json& observation,
                 nlohmann::json& reply, std::string& error);
    [[nodiscard]] nlohmann::json lookup(const SourceIdentity& source,
                                        const std::string& client_address,
                                        const std::string& destination_address);
    [[nodiscard]] nlohmann::json status();

private:
    struct Entry {
        std::string hostname;
        std::vector<std::string> cname_chain;
        std::chrono::steady_clock::time_point observed;
        std::chrono::steady_clock::time_point expires;
    };

    static constexpr std::size_t max_entries = 65536;
    static constexpr std::uint32_t max_ttl_seconds = 86400;

    void sweep_locked(std::chrono::steady_clock::time_point now);
    static std::string key(const SourceIdentity& source, const std::string& client,
                           const std::string& destination);

    std::mutex lock_;
    std::unordered_map<std::string, std::vector<Entry>> entries_;
    std::uint64_t observations_{};
    std::uint64_t addresses_stored_{};
    std::uint64_t lookups_{};
    std::uint64_t hits_{};
    std::uint64_t expired_{};
    std::uint64_t rejected_{};
    std::size_t active_records_{};
};

} // namespace sift
