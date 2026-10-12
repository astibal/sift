#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sift::sxbn {

inline constexpr std::string_view magic{"SXBN001:"};

[[nodiscard]] bool decode(const std::string& body, nlohmann::json& event,
                          std::string& payload, std::string& error);

} // namespace sift::sxbn
