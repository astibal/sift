#include <sift/engine_server.hpp>

#include <sift/engine.hpp>
#include <sift/identity.hpp>
#include <sift/sxbn.hpp>

#include <lmhttpd.hpp>
#include <microhttpd.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>

namespace sift {
namespace {

struct RequestState final : lmh::ConnectionState {
    explicit RequestState(lmh::Controller& controller) : ConnectionState(controller) {}
    bool too_large{};
};

std::string peer_ip(MHD_Connection* connection) {
    const auto* info = MHD_get_connection_info(
        connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);

    if(info == nullptr || info->client_addr == nullptr) return {};

    const auto* address = info->client_addr;
    char text[INET6_ADDRSTRLEN]{};

    if(address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        return inet_ntop(AF_INET, &ipv4->sin_addr, text, sizeof(text)) == nullptr
            ? std::string{} : std::string(text);
    }

    if(address->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        return inet_ntop(AF_INET6, &ipv6->sin6_addr, text, sizeof(text)) == nullptr
            ? std::string{} : std::string(text);
    }

    return {};
}

std::string string_field(const nlohmann::json& object, const char* name) {
    const auto found = object.find(name);

    if(found == object.end() || !found->is_string()) return {};

    return found->get<std::string>();
}

std::string identifier_field(const nlohmann::json& object, const char* name) {
    const auto found = object.find(name);

    if(found == object.end()) return {};
    if(found->is_string()) return found->get<std::string>();
    if(found->is_number_unsigned()) return std::to_string(found->get<std::uint64_t>());
    if(found->is_number_integer()) return std::to_string(found->get<std::int64_t>());

    return {};
}

class Controller final : public lmh::Controller {
public:
    Controller(const ServerConfig& config, Runtime& runtime)
        : config_(config), runtime_(runtime) {}

    bool validPath(const char* path, const char* method) override {
        const std::string_view p(path);
        const std::string_view m(method);
        return (m == "GET" &&
                (p == "/api/health" || p == "/api/status" || p == "/api/stats" ||
                 p == "/api/diagnostics")) ||
               (m == "POST" && p == config_.path);
    }

    lmh::ConnectionState* create_state() override { return new RequestState(*this); }

    int handleRequest(MHD_Connection* connection, const char* url, const char* method,
                      const char* upload_data, std::size_t* upload_data_size,
                      void** ptr) override {
        if (*ptr == nullptr) {
            *ptr = create_state();
            return MHD_YES;
        }
        auto& state = *static_cast<RequestState*>(*ptr);
        if (*upload_data_size > 0) {
            if (state.request_data.size() + *upload_data_size > config_.max_body_bytes) {
                state.too_large = true;
            } else if (!state.too_large) {
                state.request_data.append(upload_data, *upload_data_size);
            }
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (state.response_sent) return MHD_YES;

        unsigned status = 200;
        nlohmann::json reply;
        if (state.too_large) {
            status = 413;
            reply = {{"error", "request body too large"}};
        } else if (std::string_view(url) == "/api/diagnostics") {
            reply = diagnostics();
        } else if (std::string_view(url) == "/api/health" ||
                   std::string_view(url) == "/api/status" ||
                   std::string_view(url) == "/api/stats") {
            reply = runtime_.status();
        } else {
            reply = process(state.request_data, peer_ip(connection), status);
        }
        const auto body = reply.dump();
        ++requests_total_;
        request_bytes_.fetch_add(state.request_data.size(), std::memory_order_relaxed);
        last_request_at_ms_.store(wallclock_ms(), std::memory_order_relaxed);
        if(std::string_view(method) == "POST") ++post_requests_;
        else ++get_requests_;
        response_bytes_.fetch_add(body.size(), std::memory_order_relaxed);
        last_response_at_ms_.store(wallclock_ms(), std::memory_order_relaxed);
        last_status_.store(status, std::memory_order_relaxed);
        if(status >= 500) ++responses_5xx_;
        else if(status >= 400) ++responses_4xx_;
        else if(status >= 200) ++responses_2xx_;
        auto* response = MHD_create_response_from_buffer(
            body.size(), const_cast<char*>(body.data()), MHD_RESPMEM_MUST_COPY);
        if (response == nullptr) return MHD_NO;
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
        const auto result = MHD_queue_response(connection, status, response);
        MHD_destroy_response(response);
        state.response_sent = result == MHD_YES;
        return result;
    }

private:
    static std::uint64_t wallclock_ms() {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }

    nlohmann::json diagnostics() const {
        const auto uptime_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started_).count());
        return {
            {"service", "siftd"},
            {"generated_at_ms", wallclock_ms()},
            {"uptime_ms", uptime_ms},
            {"http", {
                {"requests", requests_total_.load(std::memory_order_relaxed)},
                {"get_requests", get_requests_.load(std::memory_order_relaxed)},
                {"post_requests", post_requests_.load(std::memory_order_relaxed)},
                {"request_bytes", request_bytes_.load(std::memory_order_relaxed)},
                {"response_bytes", response_bytes_.load(std::memory_order_relaxed)},
                {"responses_2xx", responses_2xx_.load(std::memory_order_relaxed)},
                {"responses_4xx", responses_4xx_.load(std::memory_order_relaxed)},
                {"responses_5xx", responses_5xx_.load(std::memory_order_relaxed)},
                {"last_status", last_status_.load(std::memory_order_relaxed)},
                {"last_request_at_ms", last_request_at_ms_.load(std::memory_order_relaxed)},
                {"last_response_at_ms", last_response_at_ms_.load(std::memory_order_relaxed)},
                {"decode_errors", decode_errors_.load(std::memory_order_relaxed)},
            }},
            {"engine", runtime_.status()},
        };
    }

    nlohmann::json process(const std::string& body, const std::string_view remote_ip,
                           unsigned& status) {
        const auto started = std::chrono::steady_clock::now();
        nlohmann::json event;
        std::string payload;
        if (std::string_view(body).starts_with(sxbn::magic)) {
            std::string error;
            if (!sxbn::decode(body, event, payload, error)) {
                ++decode_errors_;
                status = 400;
                return {{"error", error}};
            }
        } else {
            event = nlohmann::json::parse(body, nullptr, false);
            if (event.is_discarded() || !event.is_object()) {
                ++decode_errors_;
                status = 400;
                return {{"error", "invalid JSON"}};
            }
        }

        const auto action = event.value("action", "");
        if (action == "info") {
            return {{"action", "info-response"},
                    {"protocols", {{"connection-content", {"sxbn-001"}}}},
                    {"identity", {{"version", 1},
                                  {"flow_key", {"tenant", "instance", "session"}},
                                  {"fallback", "peer-ip"}}},
                    {"service", "siftd"}};
        }

        const auto identity = resolve_identity(event, remote_ip);
        const auto event_session = string_field(event, "id");

        if (action == "connection-stop") {
            if(!event_session.empty()) {
                runtime_.close(FlowKey{identity, event_session});
            }

            return nlohmann::json::object();
        }

        if (action != "connection-content") {
            return nlohmann::json::object();
        }

        const auto details = event.value("details", nlohmann::json::object());
        const auto info = details.value("info", nlohmann::json::object());
        if (payload.empty() && info.contains("content")) {
            status = 422;
            return {{"error", "JSON/base64 fallback is not implemented yet"}};
        }
        const auto side_text = info.value("side", "L");
        const auto side = side_text.empty() ? 'L' : side_text.front();
        auto session = event_session;

        if(session.empty()) session = string_field(info, "session");

        const auto anonymous = session.empty();
        if(anonymous) {
            session = "anonymous-" + std::to_string(++anonymous_sequence_);
        }

        InspectionMetadata metadata;
        metadata.payload_layer = string_field(info, "payload_layer");
        if(metadata.payload_layer.empty()) metadata.payload_layer = "tcp";
        metadata.payload_stream = identifier_field(info, "payload_stream");

        const auto starts = info.find("L7_payload_start");
        const auto ends = info.find("L7_payload_end");
        const auto encodings = info.find("L7_encoding");
        if(starts != info.end() && ends != info.end() &&
           starts->is_array() && ends->is_array() && starts->size() == ends->size()) {
            metadata.l7_payload_known = true;

            for(std::size_t index = 0; index < starts->size(); ++index) {
                if(!(*starts)[index].is_number_integer() ||
                   !(*ends)[index].is_number_integer()) {
                    metadata.l7_payload_known = false;
                    metadata.l7_payload_ranges.clear();
                    break;
                }

                const auto begin = (*starts)[index].get<std::int64_t>();
                const auto end = (*ends)[index].get<std::int64_t>();
                if(begin == -1 && end == -1) {
                    metadata.l7_payload_known = false;
                    metadata.l7_payload_ranges.clear();
                    break;
                }
                if(begin < 0 || end < begin) {
                    metadata.l7_payload_known = false;
                    metadata.l7_payload_ranges.clear();
                    break;
                }
                if(begin == end) continue;

                std::string encoding;
                if(encodings != info.end() && encodings->is_array() &&
                   index < encodings->size() && (*encodings)[index].is_string()) {
                    encoding = (*encodings)[index].get<std::string>();
                }

                metadata.l7_payload_ranges.push_back({
                    static_cast<std::size_t>(begin),
                    static_cast<std::size_t>(end),
                    std::move(encoding)});
            }
        }

        if(metadata.payload_stream.empty()) {
            for(const auto* field : {"flow.http3.stream_id", "flow.http2.stream_id"}) {
                const auto value = identifier_field(info, field);

                if(!value.empty()) {
                    metadata.payload_stream = value;
                    break;
                }
            }
        }

        for (auto item = info.begin(); item != info.end(); ++item) {
            if (!item.key().starts_with("flow.")) continue;
            auto& values = metadata.fields[item.key()];
            if (item->is_string()) values.push_back(item->get<std::string>());
            else if (item->is_boolean()) values.push_back(item->get<bool>() ? "true" : "false");
            else if (item->is_array()) {
                for (const auto& value : *item) {
                    if (value.is_string()) values.push_back(value.get<std::string>());
                    else if (value.is_boolean()) values.push_back(value.get<bool>() ? "true" : "false");
                }
            }
        }
        const FlowKey key{identity, std::move(session)};
        auto reply = verdict_json(runtime_.inspect(key, side, payload, metadata));

        if(anonymous) runtime_.close(key);

        runtime_.record_total_delay(std::chrono::steady_clock::now() - started);
        return reply;
    }

    const ServerConfig& config_;
    Runtime& runtime_;
    std::atomic_uint64_t anonymous_sequence_{};
    const std::chrono::steady_clock::time_point started_{std::chrono::steady_clock::now()};
    std::atomic_uint64_t requests_total_{};
    std::atomic_uint64_t get_requests_{};
    std::atomic_uint64_t post_requests_{};
    std::atomic_uint64_t request_bytes_{};
    std::atomic_uint64_t response_bytes_{};
    std::atomic_uint64_t responses_2xx_{};
    std::atomic_uint64_t responses_4xx_{};
    std::atomic_uint64_t responses_5xx_{};
    std::atomic_uint64_t decode_errors_{};
    std::atomic_uint64_t last_request_at_ms_{};
    std::atomic_uint64_t last_response_at_ms_{};
    std::atomic_uint64_t last_status_{};
};

} // namespace

int run_server(const ServerConfig& config, Runtime& runtime, std::atomic_bool& stop) {
    lmh::WebServer server(config.port);
    server.options().bind_address = config.bind;
    server.options().handler_should_terminate = [&stop] { return stop.load(); };
    server.options().thread_pool_size = 4;
    server.addController(std::make_shared<Controller>(config, runtime));
    return server.start() ? 0 : 1;
}

} // namespace sift
