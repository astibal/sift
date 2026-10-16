#!/usr/bin/env python3

import http.client
import json
import signal
import socket
import subprocess
import sys
import time


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
    port = free_port()
    process = subprocess.Popen(
        [sys.argv[1], "--bind", "127.0.0.1", "--port", str(port)],
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


if __name__ == "__main__":
    main()
