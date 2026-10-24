#include <sift/lored.hpp>

#include <curl/curl.h>

#include <algorithm>
#include <charconv>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace sift {
namespace {

std::size_t append_response(char* data, std::size_t size, std::size_t count,
                            void* target) {
    const auto bytes = size * count;
    static_cast<std::string*>(target)->append(data, bytes);
    return bytes;
}

std::optional<std::string> first_value(
    const InspectionMetadata& metadata,
    std::initializer_list<std::string_view> names) {
    for(const auto name : names) {
        const auto found = metadata.fields.find(std::string(name));
        if(found != metadata.fields.end() && !found->second.empty() &&
           !found->second.front().empty()) {
            return found->second.front();
        }
    }

    return std::nullopt;
}

std::optional<int> integer_value(
    const InspectionMetadata& metadata,
    std::initializer_list<std::string_view> names) {
    const auto value = first_value(metadata, names);
    if(!value.has_value()) return std::nullopt;

    int parsed{};
    const auto [end, error] = std::from_chars(
        value->data(), value->data() + value->size(), parsed);
    if(error != std::errc{} || end != value->data() + value->size() ||
       parsed < 1 || parsed > 65535) {
        return std::nullopt;
    }

    return parsed;
}

std::string protocol_hint(const InspectionMetadata& metadata,
                          const Verdict& verdict) {
    for(const auto name : {"flow.http3", "flow.http2", "flow.http1"}) {
        const auto value = first_value(metadata, {name});
        if(value == "true") return std::string(name).substr(5);
    }

    const auto alpn = first_value(metadata, {"flow.tls.alpn"});
    if(alpn.has_value()) return *alpn;

    for(const auto& match : verdict.matches) {
        if(match.signature.starts_with("protocol.")) return match.signature;
    }

    return {};
}

struct CurlHandle {
    CURL* value{curl_easy_init()};
    ~CurlHandle() { if(value != nullptr) curl_easy_cleanup(value); }
};

struct CurlHeaders {
    curl_slist* value{};
    ~CurlHeaders() { if(value != nullptr) curl_slist_free_all(value); }
};

void initialize_curl() {
    static std::once_flag once;
    static CURLcode result = CURLE_FAILED_INIT;
    std::call_once(once, [] { result = curl_global_init(CURL_GLOBAL_DEFAULT); });
    if(result != CURLE_OK) throw std::runtime_error("cannot initialize libcurl");
}

} // namespace

std::string_view lored_mode_name(const LoredMode mode) noexcept {
    switch(mode) {
    case LoredMode::disabled: return "disabled";
    case LoredMode::optional: return "optional";
    case LoredMode::required: return "required";
    }

    return "disabled";
}

LoredClient::LoredClient(LoredConfig config) : config_(std::move(config)) {
    if(config_.url.empty()) config_.mode = LoredMode::disabled;
    if(enabled()) initialize_curl();
}

bool LoredClient::enabled() const noexcept {
    return config_.mode != LoredMode::disabled;
}

bool LoredClient::required() const noexcept {
    return config_.mode == LoredMode::required;
}

nlohmann::json LoredClient::build_query(
    const InspectionMetadata& metadata, const Verdict& verdict,
    const bool include_url) const {
    nlohmann::json query = nlohmann::json::object();

    if(const auto ip = first_value(metadata, {
            "flow.destination.address", "flow.dst.ip", "flow.remote.ip"})) {
        query["ip"] = *ip;
    }

    if(const auto port = integer_value(metadata, {
            "flow.destination.port", "flow.dst.port", "flow.remote.port"})) {
        query["port"] = *port;
    }

    if(const auto transport = first_value(metadata, {
            "flow.transport", "flow.destination.transport"})) {
        query["transport"] = *transport;
    }

    if(const auto sni = first_value(metadata, {"flow.tls.sni"})) {
        query["sni"] = *sni;
    }

    if(const auto host = first_value(metadata, {
            "flow.http3.authority", "flow.http2.authority", "flow.http1.host",
            "flow.dns.forward.hostname"})) {
        query["host"] = *host;
    }

    if(include_url) {
        if(const auto url = first_value(metadata, {
                "flow.http3.url", "flow.http2.url", "flow.http1.url"})) {
            query["url"] = url->substr(0, 2048);
        }
    }

    const auto protocol = protocol_hint(metadata, verdict);
    if(!protocol.empty()) query["protocol"] = protocol.substr(0, 64);

    return query;
}

nlohmann::json LoredClient::enrich(
    const FlowKey& key, const InspectionMetadata& metadata, const Verdict& verdict,
    const LoredRequest& request, bool& attempted, bool& succeeded) {
    attempted = false;
    succeeded = false;

    if(!enabled()) return {{"status", "disabled"}};

    InspectionMetadata accumulated_metadata;
    Verdict accumulated_verdict;
    std::shared_ptr<FlowState> flow;
    {
        std::scoped_lock guard(lock_);
        auto& slot = flows_[key];
        if(!slot) slot = std::make_shared<FlowState>();
        flow = slot;
        for(const auto& [name, values] : metadata.fields) {
            if(!values.empty()) flow->metadata.fields[name] = values;
        }
        if(!verdict.matches.empty()) flow->verdict = verdict;
        accumulated_metadata = flow->metadata;
        accumulated_verdict = flow->verdict;
    }

    const auto query = build_query(
        accumulated_metadata, accumulated_verdict, request.include_url);
    if(!query.contains("ip") && !query.contains("sni") && !query.contains("host")) {
        std::scoped_lock guard(lock_);
        ++skipped_;
        return {{"status", "not-applicable"}};
    }

    const auto fingerprint = query.dump();
    const auto now = std::chrono::steady_clock::now();
    {
        std::scoped_lock guard(lock_);
        sweep_cache_locked(now);
        if(flow->resolved) {
            ++resolved_suppressed_;
            return flow->last_reply;
        }

        if(flow->fingerprints.contains(fingerprint)) {
            ++flow_cache_hits_;
            if(!flow->last_error.empty()) throw std::runtime_error(flow->last_error);
            return flow->last_reply.empty()
                ? nlohmann::json{{"status", "deduplicated"}}
                : flow->last_reply;
        }

        if(flow->queries >= config_.max_queries_per_flow) {
            ++limit_suppressed_;
            return flow->last_reply.empty()
                ? nlohmann::json{{"status", "flow-limit"}}
                : flow->last_reply;
        }

        flow->fingerprints.insert(fingerprint);
        if(const auto cached = cache_.find(fingerprint); cached != cache_.end()) {
            ++shared_cache_hits_;
            flow->last_reply = cached->second.reply;
            flow->last_error.clear();
            flow->resolved = flow->last_reply.value("status", "") == "matched";
            succeeded = true;
            return flow->last_reply;
        }

        ++flow->queries;
    }

    attempted = true;
    const auto started = std::chrono::steady_clock::now();
    CurlHandle curl;
    if(curl.value == nullptr) throw std::runtime_error("cannot initialize libcurl");

    const auto request_body = query.dump();
    std::string response;
    CurlHeaders headers;
    headers.value = curl_slist_append(headers.value, "Content-Type: application/json");

    curl_easy_setopt(curl.value, CURLOPT_URL, config_.url.c_str());
    curl_easy_setopt(curl.value, CURLOPT_HTTPHEADER, headers.value);
    curl_easy_setopt(curl.value, CURLOPT_POSTFIELDS, request_body.data());
    curl_easy_setopt(curl.value, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(request_body.size()));
    curl_easy_setopt(curl.value, CURLOPT_WRITEFUNCTION, append_response);
    curl_easy_setopt(curl.value, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.value, CURLOPT_TIMEOUT_MS,
                     static_cast<long>(config_.timeout_ms));
    curl_easy_setopt(curl.value, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(config_.timeout_ms));
    curl_easy_setopt(curl.value, CURLOPT_NOSIGNAL, 1L);

    const auto result = curl_easy_perform(curl.value);
    long status{};
    curl_easy_getinfo(curl.value, CURLINFO_RESPONSE_CODE, &status);
    const auto elapsed = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());

    std::string error;
    nlohmann::json reply;
    if(result != CURLE_OK) {
        error = curl_easy_strerror(result);
    } else if(status < 200 || status >= 300) {
        error = "HTTP " + std::to_string(status);
    } else {
        reply = nlohmann::json::parse(response, nullptr, false);
        if(reply.is_discarded() || !reply.is_object() ||
           reply.value("format", "") != "lored-verdict/1") {
            error = "invalid Lored response";
        }
    }

    {
        std::scoped_lock guard(lock_);
        ++requests_;
        latency_last_us_ = elapsed;
        latency_total_us_ += elapsed;
        latency_max_us_ = std::max(latency_max_us_, elapsed);
        if(error.empty()) {
            last_error_.clear();
            flow->last_reply = reply;
            flow->last_error.clear();
            flow->resolved = reply.value("status", "") == "matched";
            cache_[fingerprint] = {
                reply, std::chrono::steady_clock::now() +
                    std::chrono::seconds(config_.cache_ttl_seconds)};
            cache_order_.push_back(fingerprint);
            sweep_cache_locked(std::chrono::steady_clock::now());
            if(reply.value("status", "") == "matched") ++matched_;
            else ++unknown_;
        } else {
            ++failures_;
            last_error_ = error;
            flow->last_error = error;
        }
    }

    if(!error.empty()) throw std::runtime_error(error);

    succeeded = true;
    return reply;
}

void LoredClient::close(const FlowKey& key) {
    std::scoped_lock guard(lock_);
    flows_.erase(key);
}

void LoredClient::sweep_cache_locked(
    const std::chrono::steady_clock::time_point now) {
    while(!cache_order_.empty()) {
        const auto found = cache_.find(cache_order_.front());
        if(found == cache_.end()) {
            cache_order_.pop_front();
            continue;
        }

        if(found->second.expires > now && cache_.size() <= config_.max_cache_entries)
            break;

        cache_.erase(found);
        cache_order_.pop_front();
    }
}

nlohmann::json LoredClient::status() const {
    std::scoped_lock guard(lock_);
    return {
        {"mode", lored_mode_name(config_.mode)},
        {"url", config_.url},
        {"timeout_ms", config_.timeout_ms},
        {"max_queries_per_flow", config_.max_queries_per_flow},
        {"cache_ttl_seconds", config_.cache_ttl_seconds},
        {"max_cache_entries", config_.max_cache_entries},
        {"requests", requests_},
        {"matched", matched_},
        {"unknown", unknown_},
        {"failures", failures_},
        {"skipped", skipped_},
        {"flow_cache_hits", flow_cache_hits_},
        {"shared_cache_hits", shared_cache_hits_},
        {"resolved_suppressed", resolved_suppressed_},
        {"limit_suppressed", limit_suppressed_},
        {"active_flows", flows_.size()},
        {"cache_entries", cache_.size()},
        {"latency_us", {
            {"last", latency_last_us_},
            {"max", latency_max_us_},
            {"average", requests_ == 0 ? 0.0 :
                static_cast<double>(latency_total_us_) /
                static_cast<double>(requests_)}}},
        {"last_error", last_error_},
    };
}

} // namespace sift
