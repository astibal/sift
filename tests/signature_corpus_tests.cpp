#include <sift/engine.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace {

std::string decode_hex(const std::string_view encoded) {
    if(encoded.size() % 2U != 0U) throw std::runtime_error("odd hexadecimal payload");

    const auto nibble = [](const char value) -> unsigned {
        if(value >= '0' && value <= '9') return static_cast<unsigned>(value - '0');
        if(value >= 'a' && value <= 'f') return static_cast<unsigned>(value - 'a' + 10);
        if(value >= 'A' && value <= 'F') return static_cast<unsigned>(value - 'A' + 10);
        throw std::runtime_error("invalid hexadecimal payload");
    };

    std::string decoded;
    decoded.reserve(encoded.size() / 2U);
    for(std::size_t offset = 0; offset < encoded.size(); offset += 2U) {
        decoded.push_back(static_cast<char>((nibble(encoded[offset]) << 4U) |
                                            nibble(encoded[offset + 1U])));
    }
    return decoded;
}

bool contains(const sift::Verdict& verdict, const std::string_view signature) {
    return std::any_of(verdict.matches.begin(), verdict.matches.end(),
                       [signature](const sift::Match& match) {
        return match.signature == signature;
    });
}

std::string family_of(const std::string_view signature) {
    std::vector<std::string_view> parts;
    for(std::size_t begin = 0; begin <= signature.size();) {
        const auto end = signature.find('.', begin);
        parts.push_back(signature.substr(begin, end - begin));
        if(end == std::string_view::npos) break;
        begin = end + 1U;
    }

    if(parts.size() >= 4U && parts[0] == "enc" &&
       (parts[2] == "protocol" || parts[2] == "app")) {
        return std::string(parts[3]);
    }
    if(parts.size() >= 2U) return std::string(parts[1]);
    return std::string(signature);
}

} // namespace

int main(const int argc, char** argv) {
    if(argc != 2 && argc != 4) {
        std::cerr << "usage: sift_signature_corpus_tests CORPUS.json "
                     "[--family NAME]\n";
        return 2;
    }
    const auto selected_family = argc == 4 && std::string_view(argv[2]) == "--family"
        ? std::string_view(argv[3]) : std::string_view{};
    if(argc == 4 && selected_family.empty()) return 2;

    std::ifstream input(argv[1]);
    if(!input) {
        std::cerr << "cannot open signature corpus: " << argv[1] << '\n';
        return 2;
    }

    const auto corpus = nlohmann::json::parse(input);
    int failures{};
    std::size_t index{};
    std::unordered_set<std::string> covered_signatures;

    for(const auto& test : corpus.at("cases")) {
        const auto expected = test.value("expect", std::string{});
        const auto family = expected.empty() ? std::string{"negative"}
                                             : family_of(expected);
        if(!selected_family.empty() && selected_family != family) continue;

        sift::Runtime runtime;
        const auto session = "corpus-" + std::to_string(index++);
        if(!expected.empty()) covered_signatures.insert(expected);
        bool matched = expected.empty();
        bool rejected_match{};

        for(const auto& chunk : test.at("chunks")) {
            sift::InspectionMetadata metadata;
            if(const auto fields = chunk.find("fields"); fields != chunk.end()) {
                for(const auto& [name, value] : fields->items()) {
                    if(value.is_array()) {
                        metadata.fields[name] = value.get<std::vector<std::string>>();
                    } else if(value.is_boolean()) {
                        metadata.fields[name] = {value.get<bool>() ? "true" : "false"};
                    } else {
                        metadata.fields[name] = {value.get<std::string>()};
                    }
                }
            }

            auto payload = chunk.contains("hex")
                ? decode_hex(chunk.at("hex").get<std::string>())
                : chunk.value("text", std::string{});
            if(const auto pad_to = chunk.find("pad_to"); pad_to != chunk.end()) {
                const auto target = pad_to->get<std::size_t>();
                const auto padding = decode_hex(chunk.value("pad_hex", std::string{"00"}));
                if(padding.size() != 1U || target < payload.size()) {
                    throw std::runtime_error("invalid corpus padding");
                }
                payload.resize(target, padding.front());
            }
            const auto side_text = chunk.value("side", std::string{"L"});
            const auto verdict = runtime.inspect(
                session, side_text.empty() ? 'L' : side_text.front(), payload, metadata);
            matched = matched || (!expected.empty() && contains(verdict, expected));

            for(const auto& rejected : test.value(
                    "reject", std::vector<std::string>{})) {
                rejected_match = rejected_match || contains(verdict, rejected);
            }
        }

        if(!matched || rejected_match) {
            std::cerr << "FAIL " << test.value("name", expected)
                      << ": expected " << (expected.empty() ? "no rejected match" : expected)
                      << (matched ? ", rejected signature matched" : ", no match")
                      << '\n';
            ++failures;
        }
    }

    // Make adding a production signature without a replay case impossible.
    // This turns the corpus into an enforced inventory rather than a best-
    // effort collection of examples.
    if(!selected_family.empty() && index == 0U) {
        std::cerr << "FAIL corpus family has no cases: " << selected_family << '\n';
        ++failures;
    }

    if(selected_family.empty()) {
        sift::Runtime inventory_runtime;
        const auto inventory = inventory_runtime.status()
            .at("signatures").at("by_name");
        for(const auto& [signature, _] : inventory.items()) {
            if(!covered_signatures.contains(signature)) {
                std::cerr << "FAIL corpus has no positive case for " << signature << '\n';
                ++failures;
            }
        }
    }

    if(failures == 0) {
        std::cout << "signature corpus"
                  << (selected_family.empty() ? "" : " family " + std::string(selected_family))
                  << ": " << index << " cases, "
                  << covered_signatures.size() << " runtime signatures passed\n";
    }
    return failures == 0 ? 0 : 1;
}
