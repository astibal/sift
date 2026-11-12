#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include <nlohmann/json_fwd.hpp>

namespace sift {

/** Isolation boundary supplied by a capture source. */
struct SourceIdentity {
    std::string tenant{"default"};
    std::string instance;
    bool ip_fallback{};
};

/** Globally unique flow identity within the classifier process. */
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

/** Hash compatible with FlowKey's full identity-aware equality relation. */
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const noexcept;
};

/**
 * Resolve explicit tenant/instance metadata, falling back to the peer address
 * when an older sender does not yet provide a capture instance.
 */
[[nodiscard]] SourceIdentity resolve_identity(
    const nlohmann::json& event, std::string_view peer_ip);

} // namespace sift
