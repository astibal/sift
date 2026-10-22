#include <sift/engine.hpp>
#include <sift/lored.hpp>
#include <sift/structure.hpp>
#include <sift/sxbn.hpp>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <thread>

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
    check(!has_match(structure_verdict,
                     "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "runtime published an experimental TLV candidate");
    check(structure_runtime.status().at("structure").at("candidates") >= 1,
          "runtime structure candidate was not counted");
    check(structure_runtime.status().at("structure").at("published") == 0,
          "runtime reports published structure candidates");

    sift::Runtime bounded_runtime;
    const auto required_evidence = bounded_runtime.config().at(
        "required_evidence_bytes").get<std::size_t>();
    std::string config_error;
    check(bounded_runtime.configure(
              {{"evidence_bytes_per_side", required_evidence},
               {"max_flows", 2},
               {"min_idle_ttl_seconds", 600},
               {"max_idle_ttl_seconds", 86400}},
              config_error),
          "valid runtime configuration was rejected");
    (void)bounded_runtime.inspect("bounded-a", 'L', std::string(1024 * 1024, 'x'));
    auto bounded_status = bounded_runtime.status();
    check(bounded_status.at("memory").at("evidence_bytes") == required_evidence,
          "flow evidence exceeded its configured prefix limit");
    check(bounded_status.at("traffic").at("bytes") == 1024 * 1024,
          "bounded evidence truncated traffic accounting");
    const auto sparse_ttl = bounded_status.at("flows").at(
        "idle_ttl_seconds").get<std::uint64_t>();
    (void)bounded_runtime.inspect("bounded-b", 'L', "payload");
    const auto full_ttl = bounded_runtime.status().at("flows").at(
        "idle_ttl_seconds").get<std::uint64_t>();
    check(full_ttl == 600, "full flow table did not select minimum idle TTL");
    check(sparse_ttl > full_ttl, "idle TTL did not shrink with table utilization");
    (void)bounded_runtime.inspect("bounded-c", 'L', "payload");
    bounded_status = bounded_runtime.status();
    check(bounded_status.at("flows").at("active") == 2,
          "flow hard cap was not enforced");
    check(bounded_status.at("flows").at("evicted") == 1,
          "oldest flow eviction was not counted");
    check(!bounded_runtime.configure({{"evidence_bytes_per_side", 1}}, config_error),
          "unsafe evidence limit was accepted");
    check(!bounded_runtime.configure(nlohmann::json::array(), config_error),
          "non-object runtime configuration was accepted");
    check(!bounded_runtime.configure({{"unknown", 1}}, config_error),
          "unknown runtime configuration field was accepted");
    check(!bounded_runtime.configure({{"max_flows", "many"}}, config_error),
          "non-numeric runtime configuration was accepted");
    check(!bounded_runtime.configure({{"max_flows", -1}}, config_error),
          "negative runtime configuration was accepted");
    check(!bounded_runtime.configure({{"max_flows", 0}}, config_error),
          "out-of-range runtime configuration was accepted");
    check(!bounded_runtime.configure({{"min_idle_ttl_seconds", "slow"}}, config_error),
          "non-numeric minimum idle TTL was accepted");
    check(!bounded_runtime.configure({{"max_idle_ttl_seconds", 700000}}, config_error),
          "out-of-range maximum idle TTL was accepted");
    check(!bounded_runtime.configure({{"tombstone_ttl_seconds", 0}}, config_error),
          "out-of-range tombstone TTL was accepted");
    check(!bounded_runtime.configure({{"sweep_interval_seconds", 0}}, config_error),
          "out-of-range sweep interval was accepted");
    check(!bounded_runtime.configure({{"max_field_names_per_flow", 0}}, config_error),
          "out-of-range metadata field limit was accepted");
    check(!bounded_runtime.configure({{"max_values_per_field", 0}}, config_error),
          "out-of-range metadata value limit was accepted");
    check(!bounded_runtime.configure({{"max_structure_probes_per_flow", 0}}, config_error),
          "out-of-range structure probe limit was accepted");
    check(!bounded_runtime.configure(
              {{"min_idle_ttl_seconds", 20}, {"max_idle_ttl_seconds", 10}},
              config_error),
          "inverted idle TTL range was accepted");
    check(bounded_runtime.configure(
              {{"tombstone_ttl_seconds", 2},
               {"sweep_interval_seconds", 1},
               {"max_field_names_per_flow", 1},
               {"max_values_per_field", 1},
               {"max_structure_probes_per_flow", 1}},
              config_error),
          "complete valid runtime configuration was rejected");
    check(bounded_runtime.config().at("max_structure_probes_per_flow") == 1,
          "runtime configuration was not applied");

    sift::InspectionMetadata excessive_metadata;
    excessive_metadata.fields["flow.first"] = {"one"};
    (void)bounded_runtime.inspect("metadata-limits", 'L', "payload", excessive_metadata);
    excessive_metadata.fields["flow.first"] = {"two"};
    excessive_metadata.fields["flow.second"] = {"three"};
    (void)bounded_runtime.inspect("metadata-limits", 'L', "payload", excessive_metadata);
    bounded_status = bounded_runtime.status();
    check(bounded_status.at("limits").at("metadata_fields_dropped") >= 1,
          "metadata field limit was not enforced");
    check(bounded_status.at("limits").at("metadata_values_dropped") >= 1,
          "metadata value limit was not enforced");

    sift::RuntimeConfig expiring_config;
    expiring_config.min_idle_ttl_seconds = 0;
    expiring_config.max_idle_ttl_seconds = 0;
    expiring_config.sweep_interval_seconds = 0;
    expiring_config.tombstone_ttl_seconds = 0;
    sift::Runtime expiring_runtime(expiring_config);
    (void)expiring_runtime.inspect("expire", 'L', "payload");
    auto expiring_status = expiring_runtime.status();
    check(expiring_status.at("flows").at("active") == 0,
          "zero-TTL flow was not expired by status sweep");
    check(expiring_status.at("flows").at("expired") == 1,
          "idle flow expiration was not counted");
    expiring_runtime.close("already-gone");
    check(expiring_runtime.status().at("flows").at("tombstones") == 0,
          "expired tombstone was retained");

    sift::Runtime lifecycle_runtime;
    const sift::FlowKey lifecycle_key{{"default", "edge", false}, "lifecycle"};
    lifecycle_runtime.start(lifecycle_key);
    (void)lifecycle_runtime.inspect(lifecycle_key, 'L', "GET / HTTP/1.1\r\n");
    lifecycle_runtime.start(lifecycle_key);
    check(lifecycle_runtime.status().at("flows").at("active") == 1,
          "idempotent connection-start duplicated or reset a flow");
    lifecycle_runtime.close(lifecycle_key);
    check(lifecycle_runtime.inspect(lifecycle_key, 'L', "late").matches.empty(),
          "late tombstoned payload produced a verdict match");
    lifecycle_runtime.start(lifecycle_key);
    const auto lifecycle_status = lifecycle_runtime.status();
    check(lifecycle_status.at("flows").at("active") == 0,
          "late connection-start resurrected a stopped flow");
    check(lifecycle_status.at("flows").at("late_payloads_dropped") == 1,
          "late tombstoned payload was not counted");
    check(lifecycle_status.at("flows").at("tombstones") == 1,
          "connection-stop tombstone is missing");

    sift::RuntimeConfig tombstone_config;
    tombstone_config.max_flows = 1;
    sift::Runtime tombstone_runtime(tombstone_config);
    tombstone_runtime.close("old-1");
    tombstone_runtime.close("old-2");
    tombstone_runtime.close("old-3");
    check(tombstone_runtime.status().at("flows").at("tombstones") == 2,
          "tombstone hard cap was not enforced");

    sift::Runtime probe_limit_runtime;
    sift::InspectionMetadata first_layer;
    first_layer.payload_layer = "layer-one";
    sift::InspectionMetadata second_layer;
    second_layer.payload_layer = "layer-two";
    (void)probe_limit_runtime.inspect("probe-limit", 'L', "short", first_layer);
    (void)probe_limit_runtime.inspect("probe-limit", 'L', "short", second_layer);
    check(probe_limit_runtime.configure({{"max_structure_probes_per_flow", 1}},
                                        config_error),
          "structure probe limit update failed");

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
    check(!has_match(ranged_verdict,
                     "protocol.struct.tlv.16m.2x.2x.2l.le.lv"),
          "runtime published an L7 structure candidate");
    check(ranged_runtime.status().at("structure").at("candidates") >= 1,
          "extracted L7 ranges did not produce an internal candidate");

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
    check(live_stats.at("scanner").at("patterns") == 37,
          "Hyperscan pattern count is wrong");
    check(live_stats.at("scanner").at("scans") == 2,
          "Hyperscan scan count is wrong");
    check(live_stats.at("flows").at("active") == 1, "active flow not counted");
    check(live_stats.at("traffic").at("payloads") == 2, "payloads not counted");
    check(live_stats.at("signatures").at("by_name").at("protocol.http2.prior-knowledge") == 1,
          "signature count missing");
    check(live_stats.at("signatures").at("loaded") == 40,
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

    const auto rejects_sxbn = [&](std::string malformed, const std::string_view expected_error) {
        nlohmann::json malformed_event;
        std::string malformed_payload;
        std::string malformed_error;
        check(!sift::sxbn::decode(
                  malformed, malformed_event, malformed_payload, malformed_error),
              "malformed SXBN envelope was accepted");
        check(malformed_error == expected_error, "unexpected SXBN decode error");
    };
    rejects_sxbn("not-sxbn", "missing SXBN001 envelope");
    auto malformed = std::string("SXBN001:00000000:00000000");
    malformed[16] = '!';
    rejects_sxbn(malformed, "invalid SXBN length separator");
    malformed = "SXBN001:Z0000000:00000000";
    rejects_sxbn(malformed, "invalid SXBN JSON length");
    malformed = "SXBN001:00000000:Z0000000";
    rejects_sxbn(malformed, "invalid SXBN payload length");
    rejects_sxbn("SXBN001:00000000:00000000x", "SXBN envelope length mismatch");
    rejects_sxbn("SXBN001:00000001:00000000{", "invalid SXBN JSON metadata");
    rejects_sxbn("SXBN001:00000002:00000000[]", "SXBN metadata must be a JSON object");

    sift::LoredClient disabled_lore({});
    bool lore_attempted{};
    bool lore_succeeded{};
    const sift::FlowKey lore_key{{"test", "unit", false}, "disabled"};
    check(!disabled_lore.enabled() && !disabled_lore.required(),
          "empty LoreD configuration was not disabled");
    check(disabled_lore.enrich(lore_key, {}, {}, lore_attempted, lore_succeeded)
              .at("status") == "disabled",
          "disabled LoreD client returned a wrong status");
    check(disabled_lore.status().at("requests") == 0,
          "disabled LoreD client reports requests");
    disabled_lore.close(lore_key);
    check(sift::lored_mode_name(sift::LoredMode::optional) == "optional" &&
              sift::lored_mode_name(sift::LoredMode::required) == "required",
          "LoreD mode names are wrong");

    sift::LoredConfig optional_config;
    optional_config.url = "http://127.0.0.1:1/v1/query";
    optional_config.mode = sift::LoredMode::optional;
    sift::LoredClient optional_lore(optional_config);
    check(optional_lore.enrich(lore_key, {}, {}, lore_attempted, lore_succeeded)
              .at("status") == "not-applicable",
          "LoreD queried without a useful destination hint");
    check(optional_lore.status().at("skipped") == 1,
          "LoreD skipped query was not counted");

    const auto serialized = sift::verdict_json(runtime.inspect(
        "verdict-json", 'L', "GET / HTTP/1.1\r\n"));
    check(serialized.at("engine") == "siftd" &&
              serialized.at("matches").front().at("payload_layer") == "tcp",
          "verdict JSON lost engine or payload-layer metadata");

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
    check(runtime.inspect("smtp", 'L', "eh").matches.empty(),
          "fragmented SMTP greeting matched too early");
    check(runtime.inspect("smtp", 'R', "250-mail.example ESMTP\r\n").matches.empty(),
          "one-sided SMTP banner matched without a client greeting");
    check(has_match(runtime.inspect("smtp", 'L', "lo client.example\r\n"),
                    "protocol.smtp"), "fragmented SMTP dialog did not match");
    check(runtime.inspect("not-smtp", 'R', "220 service ready\r\n").matches.empty(),
          "SMTP server banner matched alone");
    check(!has_match(runtime.inspect("not-smtp", 'L', "GET / HTTP/1.1\r\n"),
                     "protocol.smtp"), "unrelated client traffic completed SMTP match");
    check(runtime.inspect("invalid-smtp-code", 'R', "22 ready\r\n").matches.empty(),
          "short SMTP response code matched");
    check(!has_match(runtime.inspect("invalid-smtp-code", 'L', "EHLO client.example\r\n"),
                     "protocol.smtp"), "invalid SMTP response completed a match");
    check(runtime.inspect("imap", 'R', "* o").matches.empty(),
          "fragmented IMAP banner matched too early");
    check(has_match(runtime.inspect("imap", 'R', "k IMAP4rev1 ready\r\n"),
                    "protocol.imap"), "fragmented IMAP banner did not match");
    check(!has_match(runtime.inspect("not-imap", 'R', "* OKAY maybe\r\n"),
                     "protocol.imap"), "invalid IMAP banner produced a match");
    sift::InspectionMetadata imaps_metadata{{{"flow.tls.alpn", {"imap"}}}};
    check(has_match(runtime.inspect("imaps", 'L', "encrypted", imaps_metadata),
                    "enc.tls.protocol.imap"), "IMAP TLS ALPN did not match");
    sift::InspectionMetadata smtp_tls_metadata{{{"flow.tls.alpn", {"smtp"}}}};
    check(!has_match(runtime.inspect("smtps", 'L', "encrypted", smtp_tls_metadata),
                     "enc.tls.protocol.imap"), "unregistered SMTP ALPN matched IMAP");
    check(runtime.inspect("pop3", 'R', "+o").matches.empty(),
          "fragmented POP3 banner matched too early");
    check(runtime.inspect("pop3", 'L', "user alice\r\n").matches.empty(),
          "one-sided POP3 client command matched without a banner");
    check(has_match(runtime.inspect("pop3", 'R', "k maildrop ready\r\n"),
                    "protocol.pop3"), "fragmented POP3 dialog did not match");
    check(runtime.inspect("not-pop3", 'R', "-ERR unavailable\r\n").matches.empty(),
          "negative POP3 response matched as a positive banner");
    check(!has_match(runtime.inspect("not-pop3", 'L', "USER alice\r\n"),
                     "protocol.pop3"), "POP3 client command matched without +OK");
    sift::InspectionMetadata pop3s_metadata{{{"flow.tls.alpn", {"pop3"}}}};
    check(has_match(runtime.inspect("pop3s", 'L', "encrypted", pop3s_metadata),
                    "enc.tls.protocol.pop3"), "POP3 TLS ALPN did not match");
    sift::InspectionMetadata youtube_video_metadata{{
        {"flow.tls.sni", {"R4---SN-8xgp1vo-2iae.GOOGLEVIDEO.com."}}}};
    check(has_match(runtime.inspect("youtube-video", 'L', "payload", youtube_video_metadata),
                    "enc.tls.app.youtube.video"), "YouTube video TLS SNI did not match");
    check(runtime.inspect("youtube-video", 'R', "more", youtube_video_metadata).matches.empty(),
          "YouTube video application matched more than once per flow");
    sift::InspectionMetadata unrelated_metadata{{
        {"flow.tls.sni", {"notgooglevideo.com"}}}};
    check(!has_match(runtime.inspect("unrelated", 'L', "payload", unrelated_metadata),
                     "enc.tls.app.youtube.video"),
          "YouTube TLS suffix matched without a domain boundary");
    sift::InspectionMetadata youtube_http_metadata{{
        {"flow.http2.authority", {"www.youtube.com"}}}};
    check(has_match(runtime.inspect("youtube-http", 'L', "payload", youtube_http_metadata),
                    "app.youtube"), "YouTube HTTP authority did not match");
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
