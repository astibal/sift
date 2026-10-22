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

} // namespace

int main(const int argc, char** argv) {
    if(argc != 2) {
        std::cerr << "usage: sift_signature_corpus_tests CORPUS.json\n";
        return 2;
    }

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
        sift::Runtime runtime;
        const auto session = "corpus-" + std::to_string(index++);
        const auto expected = test.value("expect", std::string{});
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

            const auto payload = chunk.contains("hex")
                ? decode_hex(chunk.at("hex").get<std::string>())
                : chunk.value("text", std::string{});
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
    sift::Runtime inventory_runtime;
    const auto inventory = inventory_runtime.status()
        .at("signatures").at("by_name");
    for(const auto& [signature, _] : inventory.items()) {
        if(!covered_signatures.contains(signature)) {
            std::cerr << "FAIL corpus has no positive case for " << signature << '\n';
            ++failures;
        }
    }

    if(failures == 0) {
        std::cout << "signature corpus: " << index << " cases, "
                  << covered_signatures.size() << " runtime signatures passed\n";
    }
    return failures == 0 ? 0 : 1;
}
