#include <sift/identity.hpp>

#include <functional>

#include <nlohmann/json.hpp>

namespace sift {
namespace {

std::string nonempty_string(const nlohmann::json& object, const char* key) {
    const auto found = object.find(key);

    if(found == object.end() || !found->is_string()) return {};

    auto value = found->get<std::string>();
    return value.empty() ? std::string{} : value;
}

void hash_combine(std::size_t& seed, const std::string& value) noexcept {
    const auto hash = std::hash<std::string>{}(value);
    seed ^= hash + 0x9e3779b9U + (seed << 6U) + (seed >> 2U);
}

} // namespace

std::size_t FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    std::size_t result{};
    hash_combine(result, key.source.tenant);
    hash_combine(result, key.source.instance);
    hash_combine(result, key.source.ip_fallback ? "peer-ip" : "declared");
    hash_combine(result, key.session);
    return result;
}

SourceIdentity resolve_identity(const nlohmann::json& event,
                                const std::string_view peer_ip) {
    SourceIdentity result;

    if(const auto found = event.find("identity");
       found != event.end() && found->is_object()) {
        if(auto tenant = nonempty_string(*found, "tenant"); !tenant.empty()) {
            result.tenant = std::move(tenant);
        }

        result.instance = nonempty_string(*found, "instance");
    }

    if(result.instance.empty()) {
        result.instance = nonempty_string(event, "source");
    }

    if(result.instance.empty()) {
        result.instance = peer_ip.empty() ? "unknown" : std::string(peer_ip);
        result.ip_fallback = true;
    }

    return result;
}

} // namespace sift
