#!/usr/bin/env python3

import http.client
import json
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def free_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


def request(port, method, path, body=""):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request(method, path, body, {"Content-Type": "application/json"})
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, json.loads(payload)


def wait_until_ready(port):
    for _ in range(100):
        try:
            if request(port, "GET", "/api/health")[0] == 200:
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("siftd did not become ready")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    lore_requests = []

    class LoreHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            query = json.loads(body)
            lore_requests.append(query)
            matched = query.get("sni", "").lower().rstrip(".") == "example.com"
            reply = json.dumps({
                "format": "lored-verdict/1",
                "status": "matched" if matched else "unknown",
                "candidates": [{
                    "value": "service.example",
                    "confidence": 0.85,
                    "evidence": ["tls_sni"],
                    "providers": ["test"],
                }] if matched else [],
                "truncated": False,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *_args):
            pass

    lore_port = free_port()
    lore_server = ThreadingHTTPServer(("127.0.0.1", lore_port), LoreHandler)
    lore_thread = threading.Thread(target=lore_server.serve_forever, daemon=True)
    lore_thread.start()
    port = free_port()
    process = subprocess.Popen(
        [sys.argv[1], "--bind", "127.0.0.1", "--port", str(port),
         "--lored-url", f"http://127.0.0.1:{lore_port}/v1/query"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        wait_until_ready(port)

        status, config = request(port, "GET", "/api/config")
        check(status == 200 and config["max_flows"] == 10000,
              "GET /api/config failed")

        status, reply = request(port, "POST", "/api/config", "not-json")
        check(status == 400 and reply["error"] == "invalid JSON",
              "invalid configuration JSON was accepted")

        status, reply = request(
            port, "POST", "/api/config", json.dumps({"unknown": 1}))
        check(status == 400 and "unknown configuration field" in reply["error"],
              "unknown configuration field was accepted")

        status, config = request(
            port, "POST", "/api/config", json.dumps({"max_flows": 32}))
        check(status == 200 and config["max_flows"] == 32,
              "online configuration update failed")

        status, info = request(
            port, "POST", "/webhook", json.dumps({"action": "info"}))
        check(status == 200 and info["lifecycle"]["late-content-tombstones"],
              "lifecycle capability is missing from handshake")
        check(info["enrichment"]["lored"]["mode"] == "optional",
              "Lored capability is missing from handshake")
        check(info["enrichment"]["dns_evidence"]["endpoint"] ==
              "/api/dns-observation",
              "DNS evidence capability is missing from handshake")

        status, rejected_dns = request(
            port, "POST", "/api/dns-observation", json.dumps({
                "client_address": "invalid",
                "hostname": "example.com",
                "addresses": ["203.0.113.10"],
                "ttl_seconds": 300,
            }))
        check(status == 400 and "client_address" in rejected_dns["error"],
              "invalid DNS observation was accepted")
        status, stored_dns = request(
            port, "POST", "/api/dns-observation", json.dumps({
                "format": "sift-dns-observation/1",
                "identity": {"tenant": "test", "instance": "integration"},
                "client_address": "10.0.0.42",
                "hostname": "DNS.Example.COM.",
                "addresses": ["203.0.113.10"],
                "cname_chain": ["edge.example.net"],
                "ttl_seconds": 300,
            }))
        check(status == 200 and stored_dns["status"] == "stored" and
              stored_dns["hostname"] == "dns.example.com",
              "DNS observation endpoint failed")

        content = {
            "action": "connection-content",
            "id": "lore-flow",
            "identity": {"tenant": "test", "instance": "integration"},
            "requirements": {"lored": {
                "mode": "optional",
                "include_url": False,
            }},
            "details": {"info": {
                "side": "L",
                "flow.source.address": "10.0.0.42",
                "flow.destination.address": "203.0.113.10",
                "flow.destination.port": "443",
                "flow.transport": "tcp",
                "flow.tls.sni": "Example.COM.",
                "flow.http2": True,
                "flow.http2.authority": "www.example.com",
            }},
        }
        no_lored = json.loads(json.dumps(content))
        no_lored["id"] = "no-lored-flow"
        del no_lored["requirements"]
        status, plain = request(port, "POST", "/webhook", json.dumps(no_lored))
        check(status == 200 and "lored" not in plain,
              "LoreD result was attached without a request requirement")

        status, enriched = request(port, "POST", "/webhook", json.dumps(content))
        check(status == 200 and enriched["lored"]["status"] == "matched",
              "Lored verdict was not attached")
        check(enriched["dns_evidence"]["status"] == "matched" and
              enriched["dns_evidence"]["observations"][0]["hostname"] ==
                  "dns.example.com",
              "passive DNS evidence was not attached")
        check(enriched["lored"]["candidates"][0]["value"] == "service.example",
              "wrong Lored candidate")
        check(lore_requests[-1]["sni"] == "Example.COM.",
              "SNI was not forwarded to Lored")
        check(lore_requests[-1]["protocol"] == "http2",
              "protocol hint was not forwarded to Lored")
        check(lore_requests[-1]["ip"] == "203.0.113.10" and
              lore_requests[-1]["port"] == 443 and
              lore_requests[-1]["transport"] == "tcp" and
              lore_requests[-1]["host"] == "www.example.com",
              "destination hints were not forwarded to Lored")

        check(request(port, "POST", "/webhook", json.dumps(content))[0] == 200,
              "cached LoreD verdict failed")
        changed_after_match = json.loads(json.dumps(content))
        changed_after_match["details"]["info"]["flow.http2.authority"] = \
            "richer.example.com"
        check(request(port, "POST", "/webhook",
                      json.dumps(changed_after_match))[0] == 200,
              "resolved flow suppression failed")
        check(len(lore_requests) == 1,
              "resolved flow sent another LoreD request")

        shared = json.loads(json.dumps(content))
        shared["id"] = "shared-cache-flow"
        status, shared_reply = request(port, "POST", "/webhook", json.dumps(shared))
        check(status == 200 and shared_reply["lored"]["status"] == "matched",
              "shared LoreD cache did not return the verdict")
        check(len(lore_requests) == 1,
              "shared LoreD cache sent a duplicate request")

        limited = json.loads(json.dumps(content))
        limited["id"] = "limited-flow"
        for index in range(6):
            limited["details"]["info"]["flow.tls.sni"] = f"unknown-{index}.example"
            status, limited_reply = request(
                port, "POST", "/webhook", json.dumps(limited))
            check(status == 200 and limited_reply["lored"]["status"] == "unknown",
                  "unknown LoreD verdict was not retained")
        check(len(lore_requests) == 6,
              "per-flow LoreD request limit was not enforced")

        lore_server.shutdown()
        lore_server.server_close()
        failing = json.loads(json.dumps(content))
        failing["id"] = "unavailable-flow"
        failing["details"]["info"]["flow.tls.sni"] = "unavailable.example"
        status, unavailable = request(
            port, "POST", "/webhook", json.dumps(failing))
        check(status == 200 and unavailable["lored"]["status"] == "unavailable",
              "optional LoreD failure changed the Sift response status")

        failing["requirements"]["lored"]["mode"] = "required"
        failing["id"] = "required-unavailable-flow"
        status, unavailable = request(
            port, "POST", "/webhook", json.dumps(failing))
        check(status == 503 and unavailable["lored"]["status"] == "unavailable",
              "required LoreD failure did not fail the Sift request")

        identity = {"tenant": "test", "instance": "integration"}
        start = {"action": "connection-start", "id": "flow", "identity": identity}
        stop = {"action": "connection-stop", "id": "flow", "identity": identity}
        check(request(port, "POST", "/webhook", json.dumps(start))[0] == 200,
              "connection-start failed")
        check(request(port, "POST", "/webhook", json.dumps(stop))[0] == 200,
              "connection-stop failed")

        detailed_start = {
            "action": "connection-start",
            "identity": identity,
            "details": {"info": {"session": "flow-from-details"}},
        }
        check(request(port, "POST", "/webhook", json.dumps(detailed_start))[0] == 200,
              "details.info.session lifecycle fallback failed")

        status, stats = request(port, "GET", "/api/stats")
        check(status == 200 and stats["flows"]["started"] == 2,
              "lifecycle event was not reflected in stats")
        check(stats["flows"]["tombstones"] == 1,
              "connection-stop did not create a tombstone")

        status, diagnostics = request(port, "GET", "/api/diagnostics")
        check(status == 200 and diagnostics["lored"]["requests"] == 8,
              "Lored diagnostics are missing")
        check(diagnostics["lored"]["failures"] == 2,
              "Lored failure was not diagnosed")
        check(diagnostics["lored"]["shared_cache_hits"] == 1,
              "shared LoreD cache hit was not diagnosed")
        check(diagnostics["lored"]["resolved_suppressed"] >= 2,
              "resolved LoreD flow suppression was not diagnosed")
        check(diagnostics["lored"]["limit_suppressed"] == 1,
              "LoreD per-flow request limit was not diagnosed")
        check(diagnostics["dns_evidence"]["observations"] == 1 and
              diagnostics["dns_evidence"]["hits"] >= 1 and
              diagnostics["dns_evidence"]["rejected"] == 1,
              "DNS evidence diagnostics are missing")
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            request(port, "GET", "/api/health")
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

        if process.returncode != 0:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                f"siftd exited with {process.returncode}\n{stdout}\n{stderr}")
        lore_server.shutdown()
        lore_server.server_close()


if __name__ == "__main__":
    main()
