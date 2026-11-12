#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sift::sxbn {

/** Versioned prefix for SIFT's binary-safe JSON-plus-payload envelope. */
inline constexpr std::string_view magic{"SXBN001:"};

/** Decode an SXBN request body without treating payload bytes as text. */
[[nodiscard]] bool decode(const std::string& body, nlohmann::json& event,
                          std::string& payload, std::string& error);

} // namespace sift::sxbn
