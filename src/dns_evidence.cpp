#include <sift/dns_evidence.hpp>

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <string_view>

namespace sift {
namespace {

bool valid_ip(const std::string& value) {
    in_addr ipv4{};
    in6_addr ipv6{};
    return inet_pton(AF_INET, value.c_str(), &ipv4) == 1 ||
           inet_pton(AF_INET6, value.c_str(), &ipv6) == 1;
}

std::string normalized_hostname(std::string value) {
    while(!value.empty() && value.back() == '.') value.pop_back();
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool string_array(const nlohmann::json& object, const char* name,
                  std::vector<std::string>& output, const std::size_t maximum) {
    const auto found = object.find(name);
    if(found == object.end()) return true;
    if(!found->is_array() || found->size() > maximum) return false;

    for(const auto& item : *found) {
        if(!item.is_string() || item.get_ref<const std::string&>().empty()) return false;
        output.push_back(item.get<std::string>());
    }
    return true;
}

} // namespace

std::string DnsEvidenceCache::key(const SourceIdentity& source, const std::string& client,
                                  const std::string& destination) {
    return source.tenant + '\n' + source.instance + '\n' +
           (source.ip_fallback ? "fallback\n" : "declared\n") + client + '\n' + destination;
}

void DnsEvidenceCache::sweep_locked(const std::chrono::steady_clock::time_point now) {
    for(auto bucket = entries_.begin(); bucket != entries_.end();) {
        auto& values = bucket->second;
        const auto before = values.size();
        std::erase_if(values, [now](const Entry& entry) { return entry.expires <= now; });
        const auto removed = before - values.size();
        expired_ += removed;
        active_records_ -= removed;

        if(values.empty()) bucket = entries_.erase(bucket);
        else ++bucket;
    }
}

bool DnsEvidenceCache::observe(const SourceIdentity& source,
                               const nlohmann::json& observation,
                               nlohmann::json& reply, std::string& error) {
    if(!observation.is_object()) {
        error = "DNS observation must be an object";
        return false;
    }

    const auto client = observation.value("client_address", "");
    auto hostname = normalized_hostname(observation.value("hostname", ""));
    const auto ttl = observation.value("ttl_seconds", 0U);
    std::vector<std::string> addresses;
    std::vector<std::string> cname_chain;

    if(!valid_ip(client)) error = "client_address must be an IPv4 or IPv6 address";
    else if(hostname.empty() || hostname.size() > 253) error = "hostname is invalid";
    else if(ttl == 0 || ttl > max_ttl_seconds) error = "ttl_seconds must be between 1 and 86400";
    else if(!string_array(observation, "addresses", addresses, 64) || addresses.empty()) {
        error = "addresses must be a non-empty array with at most 64 strings";
    } else if(!std::all_of(addresses.begin(), addresses.end(), valid_ip)) {
        error = "addresses contains an invalid IP address";
    } else if(!string_array(observation, "cname_chain", cname_chain, 16)) {
        error = "cname_chain must contain at most 16 strings";
    }

    if(!error.empty()) {
        std::scoped_lock guard(lock_);
        ++rejected_;
        return false;
    }

    for(auto& cname : cname_chain) cname = normalized_hostname(std::move(cname));
    const auto now = std::chrono::steady_clock::now();
    const auto expires = now + std::chrono::seconds(ttl);

    std::scoped_lock guard(lock_);
    sweep_locked(now);
    std::size_t additions{};
    for(const auto& address : addresses) {
        const auto found = entries_.find(key(source, client, address));
        if(found == entries_.end() || std::none_of(
                found->second.begin(), found->second.end(),
                [&hostname](const Entry& entry) { return entry.hostname == hostname; })) {
            ++additions;
        }
    }
    if(active_records_ + additions > max_entries) {
        ++rejected_;
        error = "DNS evidence cache capacity reached";
        return false;
    }

    for(const auto& address : addresses) {
        auto& bucket = entries_[key(source, client, address)];
        const auto removed = std::erase_if(bucket, [&hostname](const Entry& entry) {
            return entry.hostname == hostname;
        });
        active_records_ -= removed;
        bucket.push_back({hostname, cname_chain, now, expires});
        ++active_records_;
    }
    ++observations_;
    addresses_stored_ += addresses.size();
    reply = {
        {"status", "stored"},
        {"hostname", hostname},
        {"addresses", addresses.size()},
        {"ttl_seconds", ttl},
    };
    return true;
}

nlohmann::json DnsEvidenceCache::lookup(const SourceIdentity& source,
                                        const std::string& client_address,
                                        const std::string& destination_address) {
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock guard(lock_);
    sweep_locked(now);
    ++lookups_;

    const auto found = entries_.find(key(source, client_address, destination_address));
    if(found == entries_.end()) return {{"status", "unknown"}};

    ++hits_;
    nlohmann::json observations = nlohmann::json::array();
    for(const auto& entry : found->second) {
        observations.push_back({
            {"hostname", entry.hostname},
            {"cname_chain", entry.cname_chain},
            {"age_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                now - entry.observed).count()},
            {"expires_in_seconds", std::chrono::duration_cast<std::chrono::seconds>(
                entry.expires - now).count()},
        });
    }
    return {{"status", "matched"}, {"observations", std::move(observations)}};
}

nlohmann::json DnsEvidenceCache::status() {
    std::scoped_lock guard(lock_);
    sweep_locked(std::chrono::steady_clock::now());
    return {
        {"observations", observations_},
        {"addresses_stored", addresses_stored_},
        {"lookups", lookups_},
        {"hits", hits_},
        {"expired", expired_},
        {"rejected", rejected_},
        {"active_records", active_records_},
        {"capacity", max_entries},
        {"max_ttl_seconds", max_ttl_seconds},
    };
}

} // namespace sift
