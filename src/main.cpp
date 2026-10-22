#include <sift/engine.hpp>
#include <sift/engine_server.hpp>

#include <atomic>
#include <charconv>
#include <csignal>
#include <iostream>
#include <string_view>

namespace {
std::atomic_bool stop_requested{};
void stop_handler(int) { stop_requested.store(true); }
}

int main(int argc, char** argv) {
    sift::ServerConfig config;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--help") {
            std::cout << "Usage: siftd [--bind ADDRESS] [--port N] [--path PATH]"
                         " [--lored-url URL] [--lored-mode optional|required]"
                         " [--lored-timeout-ms N]\n";
            return 0;
        }
        if (arg == "--bind" && i + 1 < argc) config.bind = argv[++i];
        else if (arg == "--path" && i + 1 < argc) config.path = argv[++i];
        else if(arg == "--lored-url" && i + 1 < argc) {
            config.lored.url = argv[++i];
            if(config.lored.mode == sift::LoredMode::disabled)
                config.lored.mode = sift::LoredMode::optional;
        } else if(arg == "--lored-mode" && i + 1 < argc) {
            const std::string_view value(argv[++i]);
            if(value == "optional") config.lored.mode = sift::LoredMode::optional;
            else if(value == "required") config.lored.mode = sift::LoredMode::required;
            else {
                std::cerr << "Invalid Lored mode\n";
                return 2;
            }
        } else if(arg == "--lored-timeout-ms" && i + 1 < argc) {
            unsigned timeout{};
            const std::string_view value(argv[++i]);
            const auto [end, error] = std::from_chars(
                value.data(), value.data() + value.size(), timeout);
            if(error != std::errc{} || end != value.data() + value.size() ||
               timeout == 0 || timeout > 60000) {
                std::cerr << "Invalid Lored timeout\n";
                return 2;
            }
            config.lored.timeout_ms = timeout;
        }
        else if (arg == "--port" && i + 1 < argc) {
            unsigned port{};
            const std::string_view value(argv[++i]);
            const auto [end, error] = std::from_chars(
                value.data(), value.data() + value.size(), port);
            if (error != std::errc{} || end != value.data() + value.size() ||
                port == 0 || port > 65535) {
                std::cerr << "Invalid port\n";
                return 2;
            }
            config.port = static_cast<std::uint16_t>(port);
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            return 2;
        }
    }

    if(config.lored.mode != sift::LoredMode::disabled && config.lored.url.empty()) {
        std::cerr << "Lored mode requires --lored-url\n";
        return 2;
    }

    std::signal(SIGINT, stop_handler);
    std::signal(SIGTERM, stop_handler);
    sift::Runtime runtime;
    std::cout << "siftd listening on http://" << config.bind << ':' << config.port
              << config.path << '\n';
    return sift::run_server(config, runtime, stop_requested);
}
