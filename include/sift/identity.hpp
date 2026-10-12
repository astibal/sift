#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include <nlohmann/json_fwd.hpp>

namespace sift {

struct SourceIdentity {
    std::string tenant{"default"};
    std::string instance;
    bool ip_fallback{};
};

struct FlowKey {
    SourceIdentity source;
    std::string session;

    bool operator==(const FlowKey& other) const noexcept {
        return source.tenant == other.source.tenant &&
               source.instance == other.source.instance &&
               source.ip_fallback == other.source.ip_fallback &&
               session == other.session;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const noexcept;
};

[[nodiscard]] SourceIdentity resolve_identity(
    const nlohmann::json& event, std::string_view peer_ip);

} // namespace sift
