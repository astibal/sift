#include <sift/engine.hpp>
#include <sift/structure.hpp>
#include <sift/sxbn.hpp>

#include <algorithm>
#include <cstdio>
#include <iostream>

namespace {
int failures{};
void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

bool has_match(const sift::Verdict& verdict, const std::string_view signature) {
    return std::any_of(verdict.matches.begin(), verdict.matches.end(),
                       [signature](const sift::Match& match) {
                           return match.signature == signature;
                       });
}

bool has_candidate(const std::vector<sift::structure::TlvMatch>& candidates,
                   const std::string_view signature) {
    return std::any_of(candidates.begin(), candidates.end(),
                       [signature](const sift::structure::TlvMatch& match) {
                           return match.signature == signature;
                       });
}

bool has_one_byte_length(const std::vector<sift::structure::TlvMatch>& candidates) {
    return std::any_of(candidates.begin(), candidates.end(),
                       [](const sift::structure::TlvMatch& match) {
                           return match.signature.find(".1l.") != std::string::npos;
                       });
}

void append_u16le(std::string& output, const std::uint16_t value) {
    output.push_back(static_cast<char>(value & 0xffU));
    output.push_back(static_cast<char>(value >> 8U));
}

std::string sample_tlv() {
    std::string result(16, static_cast<char>(0xa5));

    for(std::uint16_t record = 0; record < 4; ++record) {
        append_u16le(result, static_cast<std::uint16_t>(record + 1));
        append_u16le(result, static_cast<std::uint16_t>(record + 10));

        const auto length = static_cast<std::uint16_t>(record + 8);
        append_u16le(result, length);
        result.append(length, static_cast<char>('a' + record));
    }

    return result;
}
}

int main() {
    const auto tlv_payload = sample_tlv();
    const auto tlv = sift::structure::infer_tlv_candidates(tlv_payload);
    check(!tlv.empty(), "TLV structure was not inferred");
    check(has_candidate(tlv, "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "expected TLV structure candidate is missing");
    check(has_candidate(tlv, "protocol.struct.tlv.16m.1x.1x.2l.le.lv"),
          "equally valid TLV structure ambiguity was hidden");
    check(!has_one_byte_length(tlv),
          "unsupported one-byte length candidate was emitted");
    check(sift::structure::infer_tlv_candidates(
              std::string_view(tlv_payload).substr(0, tlv_payload.size() - 3)).empty(),
          "incomplete final TLV record produced a match");
    check(!sift::structure::infer_tlv(std::string(128, 'A')).has_value(),
          "plain bytes produced a false TLV structure");

    sift::Runtime structure_runtime;
    const auto structure_verdict = structure_runtime.inspect(
        "structured-flow", 'L', tlv_payload);
    check(has_match(structure_verdict,
                    "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "runtime did not publish inferred TLV structure");
    check(structure_runtime.status().at("structure").at("matches") >= 1,
          "runtime structure match was not counted");

    sift::Runtime ranged_runtime;
    sift::InspectionMetadata empty_l7;
    empty_l7.l7_payload_known = true;
    check(ranged_runtime.inspect("empty-l7", 'L', tlv_payload, empty_l7).matches.empty(),
          "known-empty L7 payload was inspected");

    sift::InspectionMetadata beginning;
    beginning.fields["flow.http2"] = {"true"};
    beginning.payload_stream = "19";
    beginning.l7_payload_known = true;
    beginning.l7_payload_ranges = {{10, 30, ""}, {35, 55, ""}};
    const auto first_l7 = std::string(10, 'x') + tlv_payload.substr(0, 20) +
        std::string(5, 'y') + tlv_payload.substr(20, 20);
    check(!has_match(ranged_runtime.inspect("ranged", 'L', first_l7, beginning),
                     "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "partial L7 unit matched too early");

    sift::InspectionMetadata continuation;
    continuation.fields["flow.http2"] = {"true"};
    continuation.payload_stream = "19";
    continuation.l7_payload_known = true;
    continuation.l7_payload_ranges = {{7, 7 + tlv_payload.size() - 40, ""}};
    const auto second_l7 = std::string(7, 'z') + tlv_payload.substr(40);
    const auto ranged_verdict = ranged_runtime.inspect(
        "ranged", 'L', second_l7, continuation);
    check(has_match(ranged_verdict,
                    "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "extracted L7 ranges did not produce a structure match");
    if(!ranged_verdict.matches.empty()) {
        check(ranged_verdict.matches.front().side == 'L',
              "structure match lost its direction");
        check(ranged_verdict.matches.front().payload_layer == "http2.payload",
              "structure match lost its payload layer");
    }

    sift::Runtime isolated_runtime;
    beginning.payload_stream = "23";
    check(!has_match(isolated_runtime.inspect("isolated", 'L', first_l7, beginning),
                     "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "isolated structure prefix matched too early");
    continuation.payload_stream = "29";
    check(isolated_runtime.inspect("isolated", 'L', second_l7, continuation).matches.empty(),
          "L7 structure state leaked between streams");
    continuation.payload_stream = "23";
    check(isolated_runtime.inspect("isolated", 'R', second_l7, continuation).matches.empty(),
          "L7 structure state leaked between directions");

    sift::Runtime encoding_runtime;
    beginning.payload_stream = "31";
    beginning.l7_payload_ranges = {{10, 30, "gzip"}, {35, 55, "gzip"}};
    check(!has_match(encoding_runtime.inspect("encoding", 'L', first_l7, beginning),
                     "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "encoded structure prefix matched too early");
    continuation.payload_stream = "31";
    check(encoding_runtime.inspect("encoding", 'L', second_l7, continuation).matches.empty(),
          "L7 structure state leaked between encodings");

    const auto declared_identity = sift::resolve_identity(
        nlohmann::json{{"identity", {{"tenant", "acme"}, {"instance", "edge-a"}}},
                       {"source", "legacy"}},
        "192.0.2.10");
    check(declared_identity.tenant == "acme", "declared tenant was ignored");
    check(declared_identity.instance == "edge-a", "declared instance was ignored");
    check(!declared_identity.ip_fallback, "declared identity marked as fallback");

    const auto legacy_identity = sift::resolve_identity(
        nlohmann::json{{"source", "legacy-edge"}}, "192.0.2.11");
    check(legacy_identity.tenant == "default", "legacy tenant default is wrong");
    check(legacy_identity.instance == "legacy-edge", "legacy source was ignored");

    const auto fallback_identity = sift::resolve_identity(
        nlohmann::json::object(), "192.0.2.12");
    check(fallback_identity.instance == "192.0.2.12", "peer IP fallback is wrong");
    check(fallback_identity.ip_fallback, "peer IP fallback was not reported");

    sift::Runtime tenant_runtime;
    const sift::FlowKey tenant_a{{"default", "edge-a", false}, "shared-session"};
    const sift::FlowKey tenant_b{{"default", "edge-b", false}, "shared-session"};
    const sift::FlowKey tenant_c{{"tenant-c", "edge-a", false}, "shared-session"};
    check(tenant_runtime.inspect(tenant_a, 'L', "PRI * HTTP/2.0\r\n").matches.empty(),
          "first tenant fragment matched too early");
    check(tenant_runtime.inspect(tenant_b, 'L', "\r\nSM\r\n\r\n").matches.empty(),
          "flow state leaked between producer instances");
    check(tenant_runtime.inspect(tenant_c, 'L', "\r\nSM\r\n\r\n").matches.empty(),
          "flow state leaked between tenants");
    check(has_match(tenant_runtime.inspect(tenant_a, 'L', "\r\nSM\r\n\r\n"),
                    "protocol.http2.prior-knowledge"),
          "tenant-scoped fragmented flow did not match");
    tenant_runtime.close(tenant_a);
    check(tenant_runtime.status().at("flows").at("active") == 2,
          "closing one tenant removed another tenant's flow");
    check(tenant_runtime.status().at("identity").at("tenants_seen") == 2,
          "tenant identity stats are wrong");
    check(tenant_runtime.status().at("identity").at("instances_seen") == 3,
          "producer instance stats are wrong");

    sift::Runtime fallback_runtime;
    const auto fallback_verdict = fallback_runtime.inspect(
        sift::FlowKey{fallback_identity, "flow"}, 'L', "payload");
    check(fallback_verdict.action == "accept", "fallback flow was not inspected");
    check(fallback_runtime.status().at("identity").at("ip_fallback_requests") == 1,
          "peer IP fallback request was not counted");

    sift::Runtime runtime;
    auto first = runtime.inspect("flow-1", 'L', "PRI * HTTP/2.0\r\n");
    check(first.matches.empty(), "fragment must remain pending");
    auto second = runtime.inspect("flow-1", 'L', "\r\nSM\r\n\r\n");
    check(second.matches.size() == 1, "fragmented HTTP/2 preface must match");
    check(second.matches.front().signature == "protocol.http2.prior-knowledge", "wrong match");

    const auto live_stats = runtime.status();
    check(live_stats.at("scanner").at("name") == "hyperscan",
          "Hyperscan scanner metadata missing");
    check(live_stats.at("scanner").at("mode") == "stream",
          "Hyperscan stream mode missing");
    check(live_stats.at("scanner").at("patterns") == 23,
          "Hyperscan pattern count is wrong");
    check(live_stats.at("scanner").at("scans") == 2,
          "Hyperscan scan count is wrong");
    check(live_stats.at("flows").at("active") == 1, "active flow not counted");
    check(live_stats.at("traffic").at("payloads") == 2, "payloads not counted");
    check(live_stats.at("signatures").at("by_name").at("protocol.http2.prior-knowledge") == 1,
          "signature count missing");
    check(live_stats.at("signatures").at("loaded") == 24,
          "loaded signature count is wrong");
    check(live_stats.at("timing").at("engine_delay_us").at("samples") == 2,
          "engine timing samples missing");
    runtime.record_total_delay(std::chrono::microseconds(125));
    const auto timed_stats = runtime.status();
    check(timed_stats.at("timing").at("total_delay_us").at("samples") == 1,
          "total delay timing samples missing");
    check(timed_stats.at("timing").at("total_delay_us").at("last") == 125.0,
          "total delay timing value is wrong");
    check(timed_stats.at("timing").at("total_delay_us").at("median") == 125.0,
          "total delay median is wrong");
    check(timed_stats.at("timing").at("engine_delay_us").at("median_samples") == 2,
          "engine median sample count is wrong");

    runtime.close("flow-1");
    const auto closed_stats = runtime.status();
    check(closed_stats.at("flows").at("active") == 0, "closed flow retained");
    check(closed_stats.at("flows").at("closed") == 1, "closed flow not counted");

    const std::string metadata = R"({"action":"connection-content","id":"x","details":{"info":{"session":"x","side":"L","payload_length":8}}})";
    char prefix[26]{};
    std::snprintf(prefix, sizeof(prefix), "SXBN001:%08X:%08X",
                  static_cast<unsigned>(metadata.size()), 8U);
    std::string wire(prefix, 25);
    wire += metadata;
    wire.append("AMQP\0\0\x09\x01", 8);
    nlohmann::json event;
    std::string payload;
    std::string error;
    check(sift::sxbn::decode(wire, event, payload, error), "SXBN decode failed");
    check(payload.size() == 8, "SXBN payload lost");
    check(runtime.inspect("x", 'L', payload).matches.size() == 1, "AMQP did not match");

    check(has_match(runtime.inspect("http1", 'L', "GET / HTTP/1.1\r\n"),
                    "protocol.http1.request"), "HTTP/1 request did not match");
    check(has_match(runtime.inspect("smb2", 'R', std::string_view{"\0\0\0\0\xfeSMB", 8}),
                    "protocol.smb2.netbios"), "SMB2 did not match");
    check(runtime.inspect("ssh", 'L', "SSH-2.0-client\r\n").matches.empty(),
          "one-sided SSH banner matched too early");
    check(has_match(runtime.inspect("ssh", 'R', "SSH-2.0-server\r\n"),
                    "protocol.ssh.banner-both"), "bidirectional SSH did not match");
    check(has_match(runtime.inspect("ajp", 'L', std::string_view{"\x12\x34\0\x01\x0a", 5}),
                    "protocol.ajp13.ping"), "AJP ping did not match");
    check(has_match(runtime.inspect("memcache", 'L', "get key\r\n"),
                    "protocol.memcached.ascii"), "memcached ASCII did not match");
    sift::InspectionMetadata youtube_video_metadata{{
        {"flow.tls.sni", {"R4---SN-8xgp1vo-2iae.GOOGLEVIDEO.com."}}}};
    check(has_match(runtime.inspect("youtube-video", 'L', "payload", youtube_video_metadata),
                    "app.youtube.video"), "YouTube video hostname did not match");
    check(runtime.inspect("youtube-video", 'R', "more", youtube_video_metadata).matches.empty(),
          "YouTube video application matched more than once per flow");
    sift::InspectionMetadata unrelated_metadata{{
        {"flow.tls.sni", {"notgooglevideo.com"}}}};
    check(!has_match(runtime.inspect("unrelated", 'L', "payload", unrelated_metadata),
                     "app.youtube.video"), "YouTube suffix matched without a domain boundary");
    sift::InspectionMetadata http2_metadata{{{"flow.http2", {"true"}}}};
    check(has_match(runtime.inspect("requestor-h2", 'L', "payload", http2_metadata),
                    "protocol.http2"), "requestor HTTP/2 confirmation did not match");
    sift::InspectionMetadata http1_metadata{{
        {"flow.http1", {"true"}},
        {"flow.http1.host", {"www.example.test"}},
        {"flow.http1.url", {"https://www.example.test/index.html"}}}};
    check(has_match(runtime.inspect("requestor-h1", 'L', "payload", http1_metadata),
                    "protocol.http1"), "requestor HTTP/1 confirmation did not match");
    sift::InspectionMetadata http3_metadata{{
        {"flow.http3", {"true"}},
        {"flow.http3.authority", {"www.example.test"}},
        {"flow.http3.path", {"/index.html"}}}};
    check(has_match(runtime.inspect("requestor-h3", 'L', "payload", http3_metadata),
                    "protocol.http3"), "requestor HTTP/3 confirmation did not match");
    return failures == 0 ? 0 : 1;
}
