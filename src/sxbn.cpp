#include <sift/sxbn.hpp>

#include <charconv>
#include <cstdint>

namespace sift::sxbn {

bool decode(const std::string& body, nlohmann::json& event,
            std::string& payload, std::string& error) {
    constexpr std::size_t prefix_size = 25;
    if (body.size() < prefix_size || !std::string_view(body).starts_with(magic)) {
        error = "missing SXBN001 envelope";
        return false;
    }
    if (body[16] != ':') {
        error = "invalid SXBN length separator";
        return false;
    }
    std::uint32_t json_size{};
    std::uint32_t payload_size{};
    const auto json_first = body.data() + magic.size();
    const auto json_last = body.data() + 16;
    const auto payload_first = body.data() + 17;
    const auto payload_last = body.data() + prefix_size;
    const auto parsed_json = std::from_chars(json_first, json_last, json_size, 16);
    const auto parsed_payload = std::from_chars(payload_first, payload_last, payload_size, 16);
    if (parsed_json.ec != std::errc{} || parsed_json.ptr != json_last) {
        error = "invalid SXBN JSON length";
        return false;
    }
    if (parsed_payload.ec != std::errc{} || parsed_payload.ptr != payload_last) {
        error = "invalid SXBN payload length";
        return false;
    }
    const auto content_size = static_cast<std::uint64_t>(json_size) + payload_size;
    if (content_size != body.size() - prefix_size) {
        error = "SXBN envelope length mismatch";
        return false;
    }
    try {
        event = nlohmann::json::parse(
            body.begin() + static_cast<std::ptrdiff_t>(prefix_size),
            body.begin() + static_cast<std::ptrdiff_t>(prefix_size + json_size));
    } catch (const nlohmann::json::exception&) {
        error = "invalid SXBN JSON metadata";
        return false;
    }
    if (!event.is_object()) {
        error = "SXBN metadata must be a JSON object";
        return false;
    }
    payload.assign(body.data() + static_cast<std::ptrdiff_t>(prefix_size + json_size),
                   payload_size);
    return true;
}

} // namespace sift::sxbn
