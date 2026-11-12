#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <sift/lored.hpp>

namespace sift {

/** HTTP adapter settings and optional LoreD integration limits. */
struct ServerConfig {
    std::string bind{"127.0.0.1"};
    std::uint16_t port{18081};
    std::string path{"/webhook"};
    std::size_t max_body_bytes{16U * 1024U * 1024U};
    LoredConfig lored;
};

class Runtime;
/** Serve webhook requests until stop becomes true; returns a process exit code. */
int run_server(const ServerConfig& config, Runtime& runtime, std::atomic_bool& stop);

} // namespace sift
