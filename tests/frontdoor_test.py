"""TLS frontdoor regression tests; run: python3 -m unittest discover -s tests -p frontdoor_test.py."""
import importlib.util
import base64
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

SPEC = importlib.util.spec_from_file_location("frontdoor", Path(__file__).resolve().parents[1] / "server/port443-mux.py")
mux = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mux)
PUBLIC_HOST = "gateway.example.com"
CONNECT_HOST = "203.0.113.1"
CADDY_BIN = os.environ.get("CADDY_TEST_BIN") or shutil.which("caddy")


def client_hello(host=PUBLIC_HOST):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    client = context.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def record(payload):
    return b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload


def read_wire(data, **kwargs):
    a, b = socket.socketpair()
    def sender():
        try:
            a.sendall(data)
            a.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    worker = threading.Thread(target=sender)
    worker.start()
    try:
        return mux.read_client_hello(b, **kwargs)
    finally:
        b.close()
        a.close()
        worker.join(timeout=1)


class Upstream:
    def __init__(self):
        self.sent = bytearray()
        self.closed = False

    def sendall(self, data):
        self.sent.extend(data)

    def close(self):
        self.closed = True


@unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is unavailable")
class ComposeNetworkTests(unittest.TestCase):
    def test_rendered_dynamic_pool_cannot_take_frontdoor_address(self):
        # Inspect Compose's resolved model without requiring a Docker daemon.
        # A static address alone is not reserved until its container starts;
        # dependencies starting first must allocate from a separate IP range.
        compose = Path(__file__).resolve().parents[1] / "server/compose.yaml"
        defaults = {"PUBLIC_HOST": PUBLIC_HOST, "CONNECT_HOST": CONNECT_HOST}
        custom = {"FRONTDOOR_SUBNET": "192.0.2.0/24", "TRANSPORT_IP_RANGE": "192.0.2.128/25", "FRONTDOOR_IP": "192.0.2.2"}
        for overrides in ({}, custom):
            with self.subTest(overrides=overrides):
                env = os.environ.copy()
                for name in ("FRONTDOOR_SUBNET", "TRANSPORT_IP_RANGE", "FRONTDOOR_IP"):
                    env.pop(name, None)
                env.update(defaults)
                env.update(overrides)
                result = subprocess.run(
                    ["docker", "compose", "--env-file", os.devnull, "-f", str(compose), "config", "--format", "json"],
                    env=env, capture_output=True, text=True, timeout=15, check=True,
                )
                config = json.loads(result.stdout)
                allocation = config["networks"]["transport"]["ipam"]["config"][0]
                subnet = ipaddress.ip_network(allocation["subnet"])
                pool = ipaddress.ip_network(allocation["ip_range"])
                frontdoor = ipaddress.ip_address(config["services"]["frontdoor"]["networks"]["transport"]["ipv4_address"])
                self.assertTrue(pool.subnet_of(subnet))
                self.assertIn(frontdoor, subnet)
                self.assertNotIn(frontdoor, pool)


@unittest.skipUnless(CADDY_BIN, "Set CADDY_TEST_BIN to exercise real Caddy error logs")
class CaddyLogTests(unittest.TestCase):
    def test_runtime_error_log_omits_uri_and_headers(self):
        template = (Path(__file__).resolve().parents[1] / "server/Caddyfile.template").read_text()
        global_config = template.split("# Replace __DOMAIN__", 1)[0]
        uri_marker, header_marker = "FIXTURE_ONLY_URI", "FIXTURE_ONLY_REFERER"
        for filtered in (False, True):
            with self.subTest(filtered=filtered), tempfile.TemporaryDirectory(prefix="caddy-log-fixture-") as directory:
                # Hold an unavailable upstream port; the explicit short dial
                # deadline also makes the fixture deterministic on macOS.
                with socket.socket() as unavailable, socket.socket() as reservation:
                    unavailable.bind(("127.0.0.1", 0))
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                    reservation.close()
                    config = Path(directory) / "Caddyfile"
                    config.write_text((global_config if filtered else "{\n admin off\n}\n") +
                        f"http://127.0.0.1:{port} {{\n reverse_proxy 127.0.0.1:{unavailable.getsockname()[1]} {{\n"
                        " transport http {\n dial_timeout 100ms\n }\n }\n}\n")
                    env = os.environ.copy()
                    env["FRONTDOOR_IP"] = "127.0.0.1"
                    env["XDG_DATA_HOME"] = directory
                    env["XDG_CONFIG_HOME"] = directory
                    process = subprocess.Popen([CADDY_BIN, "run", "--config", str(config), "--adapter", "caddyfile"],
                        env=env, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        deadline = time.monotonic() + 5
                        while True:
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                    break
                            except OSError:
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    self.fail("Caddy fixture did not start")
                                time.sleep(0.02)
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                        try:
                            connection.request("GET", "/magic?token=" + uri_marker,
                                headers={"Referer": "https://example.invalid/?token=" + header_marker})
                            response = connection.getresponse()
                            self.assertEqual(response.status, 502)
                            response.read()
                        finally:
                            connection.close()
                    finally:
                        process.terminate()
                        stdout, stderr = process.communicate(timeout=3)
                    logs = stdout + stderr
                    errors = [json.loads(line) for line in logs.splitlines() if line.startswith("{") and '"http.log.error"' in line]
                    self.assertEqual(len(errors), 1)
                    self.assertEqual(errors[0]["status"], 502)
                    self.assertEqual(errors[0]["request"]["method"], "GET")
                    if filtered:
                        self.assertNotIn(uri_marker, logs)
                        self.assertNotIn(header_marker, logs)
                        self.assertNotIn("uri", errors[0]["request"])
                        self.assertNotIn("headers", errors[0]["request"])
                    else:
                        self.assertIn(uri_marker, logs)
                        self.assertIn(header_marker, logs)


@unittest.skipUnless(CADDY_BIN, "Set CADDY_TEST_BIN to exercise real Caddy Basic authentication")
class CaddyAuthTests(unittest.TestCase):
    def test_template_basic_auth_controls_gateway_identity_and_public_assets(self):
        requests = []

        class GatewayFixture(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                user = self.headers.get("X-Remote-User", "")
                requests.append({"path": self.path, "method": self.command, "user": user})
                body = json.dumps({"user": user}).encode()
                self.send_response(401 if self.path == "/__authfail" else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GatewayFixture)
        backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        backend_thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="caddy-auth-fixture-") as directory, socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
                reservation.close()
                # Both accounts and the password are synthetic. Generate the
                # hash in memory; never print credentials or adapted config.
                password = "FIXTURE_ONLY_PASSWORD"
                hashed = subprocess.run([CADDY_BIN, "hash-password", "--plaintext", password],
                    capture_output=True, text=True, timeout=15, check=True).stdout.strip()
                template = (Path(__file__).resolve().parents[1] / "server/Caddyfile.template").read_text()
                # Exercise the real auth/public routes without obtaining any
                # certificates or contacting the production gateway.
                rendered = template.split("# The direct CONNECT endpoint", 1)[0]
                rendered = rendered.replace("__DOMAIN__", f"http://127.0.0.1:{port}")
                rendered = rendered.replace("__BASIC_AUTH_USER__ __BASIC_AUTH_HASH__",
                    f"fixture-alice {hashed}\n            fixture-bob {hashed}")
                rendered = rendered.replace("gateway:8088", f"127.0.0.1:{backend.server_port}")
                config = Path(directory) / "Caddyfile"
                config.write_text(rendered)
                env = os.environ.copy()
                env.update({"FRONTDOOR_IP": "127.0.0.1", "XDG_DATA_HOME": directory, "XDG_CONFIG_HOME": directory})
                process = subprocess.Popen([CADDY_BIN, "run", "--config", str(config), "--adapter", "caddyfile"],
                    env=env, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                self.fail("Caddy auth fixture did not start")
                            time.sleep(0.02)

                    def request(path, headers=None):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                        try:
                            connection.request("GET", path, headers=headers or {})
                            response = connection.getresponse()
                            return response.status, dict(response.getheaders()), response.read()
                        finally:
                            connection.close()

                    def basic(user, secret=password):
                        return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()

                    for headers in ({}, {"Authorization": basic("fixture-alice", "WRONG_FIXTURE_PASSWORD")},
                            {"X-Remote-User": "fixture-bob"}):
                        requests.clear()
                        status, response_headers, _ = request("/__health", headers)
                        self.assertEqual(status, 401)
                        self.assertTrue(response_headers.get("Www-Authenticate", "").startswith("Basic "))
                        self.assertEqual([(item["path"], item["method"]) for item in requests],
                            [("/__ban-check", "GET"), ("/__authfail", "POST")])
                    for user, spoof in (("fixture-alice", "fixture-bob"), ("fixture-bob", "fixture-alice")):
                        requests.clear()
                        status, _, body = request("/__health", {"Authorization": basic(user), "X-Remote-User": spoof})
                        self.assertEqual(status, 200)
                        self.assertEqual(json.loads(body)["user"], user)
                        self.assertEqual(requests[-1], {"path": "/__health", "method": "GET", "user": user})
                    for path in ("/p/assets-proxy.anthropic.com/fixture.js", "/p/assets.claude.ai/fixture.js"):
                        requests.clear()
                        status, _, body = request(path, {"X-Remote-User": "fixture-bob"})
                        self.assertEqual(status, 200)
                        self.assertEqual(json.loads(body)["user"], "")
                        self.assertEqual(requests, [{"path": path, "method": "GET", "user": ""}])
                    for path in ("/__ban-check", "/__authfail"):
                        requests.clear()
                        self.assertEqual(request(path)[0], 404)
                        self.assertFalse(requests)
                finally:
                    process.terminate()
                    process.communicate(timeout=3)
        finally:
            backend.shutdown()
            backend.server_close()
            backend_thread.join(timeout=1)


class FrontdoorLoadTests(unittest.TestCase):
    def test_cold_asset_burst_capacity_rejection_and_recovery(self):
        self.assertEqual(mux.MAX_CONNECTIONS, 1024)
        # This process owns both peers of every relayed connection.
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        needed = 3 * mux.MAX_CONNECTIONS + 256
        if soft != resource.RLIM_INFINITY and soft < needed:
            limit = needed if hard == resource.RLIM_INFINITY else min(needed, hard)
            if limit < needed:
                self.skipTest("open-file limit is too low for the capacity fixture")
            resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        hello = client_hello()
        forwarded, errors, upstreams, clients = [], [], [], []
        lock, stop = threading.Lock(), threading.Event()
        backend = socket.socket()
        backend.bind(("127.0.0.1", 0))
        backend.listen(2048)
        backend.settimeout(0.1)

        def accept_upstreams():
            while not stop.is_set():
                try:
                    upstream, _ = backend.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with lock:
                    upstreams.append(upstream)
                upstream.settimeout(2)
                data = bytearray()
                try:
                    while len(data) < len(hello) + 128:
                        chunk = upstream.recv(len(hello) + 128 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                        header, separator, payload = data.partition(b"\r\n")
                        if separator and len(payload) >= len(hello):
                            with lock:
                                if header.startswith(b"PROXY TCP4 ") and payload == hello:
                                    forwarded.append(True)
                                else:
                                    errors.append("incorrect forwarded handshake")
                            break
                except OSError:
                    if not stop.is_set():
                        errors.append("fixture upstream read failed")

        worker = threading.Thread(target=accept_upstreams)
        worker.start()
        process = None
        try:
            with tempfile.TemporaryDirectory(prefix="frontdoor-load-fixture-") as directory:
                ready, report = Path(directory) / "ready", Path(directory) / "reports"
                # A separate mux process is essential: production owns two
                # sockets per connection, while the test also owns both peers.
                # Keeping peers in this parent models the actual 1024-FD limit.
                shim = textwrap.dedent('''
                    import importlib.util, pathlib, socket, sys
                    spec = importlib.util.spec_from_file_location("mux_fixture", sys.argv[1])
                    mux = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mux)
                    mux.CADDY = ("127.0.0.1", int(sys.argv[2]))
                    mux.CAPACITY_WAIT = 1.0
                    native_socket, native_diagnostics = socket.socket, mux.Diagnostics
                    ready, reports = pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
                    class FixtureSocket(native_socket):
                        def bind(self, address):
                            super().bind(("127.0.0.1", 0) if address == ("0.0.0.0", 443) else address)
                        def listen(self, backlog):
                            super().listen(backlog)
                            ready.write_text(str(self.getsockname()[1]))
                    class FixtureDiagnostics(native_diagnostics):
                        def __init__(self):
                            def output(line):
                                with reports.open("a") as target:
                                    target.write(line + "\\n")
                            super().__init__(output)
                        def report_forever(self, stop, interval=30.0):
                            super().report_forever(stop, interval=0.02)
                    mux.socket.socket, mux.Diagnostics = FixtureSocket, FixtureDiagnostics
                    mux.main()
                ''')
                env = os.environ.copy()
                env.update({"PUBLIC_HOST": PUBLIC_HOST, "CONNECT_HOST": CONNECT_HOST, "FRONTDOOR_DIAGNOSTICS": "1"})
                process = subprocess.Popen([sys.executable, "-c", shim, str(SPEC.origin), str(backend.getsockname()[1]), str(ready), str(report)],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                def wait_for(predicate, message):
                    deadline = time.monotonic() + 10
                    while not predicate():
                        self.assertIsNone(process.poll(), "mux fixture exited")
                        if time.monotonic() >= deadline:
                            self.fail(message)
                        time.sleep(0.02)

                def reports():
                    entries = []
                    for line in report.read_text().splitlines() if report.exists() else []:
                        try:
                            entries.append(json.loads(line))
                        except ValueError:
                            pass  # The reporter may be writing the final line.
                    return entries

                def open_client():
                    client = socket.create_connection(("127.0.0.1", int(ready.read_text())), timeout=3)
                    clients.append(client)
                    client.sendall(hello)

                wait_for(ready.exists, "mux fixture did not bind")
                # A Claude page load through Cloudflare opens hundreds of origin
                # connections at once; all of them must be forwarded.
                for _ in range(600):
                    open_client()
                wait_for(lambda: len(forwarded) >= 600, "cold asset burst was not forwarded")
                for _ in range(mux.MAX_CONNECTIONS - 600):
                    open_client()
                wait_for(lambda: len(forwarded) == mux.MAX_CONNECTIONS, "bounded capacity was not reached")
                wait_for(lambda: any(entry["active"] == mux.MAX_CONNECTIONS for entry in reports()), "capacity peak not reported")
                proc_fds = Path(f"/proc/{process.pid}/fd")
                if proc_fds.exists():
                    self.assertLessEqual(len(list(proc_fds.iterdir())), 2 * mux.MAX_CONNECTIONS + 8)
                for _ in range(3):
                    with socket.create_connection(("127.0.0.1", int(ready.read_text())), timeout=3) as excess:
                        self.assertEqual(excess.recv(1), b"")
                wait_for(lambda: sum(entry["capacity_rejected"] for entry in reports()) == 3, "over-capacity drops not reported")
                self.assertEqual(len(forwarded), mux.MAX_CONNECTIONS)
                # An arrival at full capacity waits for a freed slot instead of being dropped.
                open_client()
                # A reset ends that relay at once; its slot then admits the waiter.
                freed = clients.pop(0)
                freed.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                freed.close()
                wait_for(lambda: len(forwarded) == mux.MAX_CONNECTIONS + 1, "waiting arrival was not forwarded")
                self.assertEqual(sum(entry["capacity_rejected"] for entry in reports()), 3)
                # Free all occupied slots, then verify the listener recovers.
                with lock:
                    occupied = clients + upstreams[:]
                    clients.clear()
                for sock in occupied:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    sock.close()
                wait_for(lambda: bool(reports()) and reports()[-1]["active"] == 0, "closed slots were not released")
                for _ in range(16):
                    open_client()
                wait_for(lambda: len(forwarded) == mux.MAX_CONNECTIONS + 17, "listener did not recover after saturation")
                self.assertFalse(errors)
                self.assertLessEqual(max(entry["active_peak"] for entry in reports()), mux.MAX_CONNECTIONS)
        finally:
            if process is not None:
                process.terminate()
                process.communicate(timeout=5)
            stop.set()
            backend.close()
            for sock in clients + upstreams:
                sock.close()
            worker.join(timeout=3)


class DiagnosticsTests(unittest.TestCase):
    def test_interval_reset_preserves_active_count_and_rejects_dynamic_keys(self):
        output = []
        diagnostics = mux.Diagnostics(output.append)
        diagnostics.accepted()
        diagnostics.accepted()
        diagnostics.closed()
        diagnostics.record("capacity_rejected")
        self.assertFalse(output)  # No per-request output.
        with self.assertRaises(ValueError):
            diagnostics.record("PRIVATE_CLIENT_IDENTITY")
        diagnostics.emit()
        first = json.loads(output[0])
        self.assertEqual((first["accepted"], first["active"], first["active_peak"]), (2, 1, 2))
        self.assertEqual(first["capacity_rejected"], 1)
        self.assertEqual(set(first), set(mux.DIAGNOSTIC_CATEGORIES) | {"event", "active", "active_peak"})
        diagnostics.emit()
        self.assertEqual(len(output), 1)
        diagnostics.closed()
        diagnostics.emit()
        second = json.loads(output[1])
        self.assertEqual((second["accepted"], second["active"], second["active_peak"]), (0, 0, 1))
        self.assertNotIn("PRIVATE_CLIENT_IDENTITY", "".join(output))

    def test_blocked_output_does_not_lock_connection_accounting(self):
        entered, release, counted = threading.Event(), threading.Event(), threading.Event()

        def output(_line):
            entered.set()
            release.wait(1)

        diagnostics = mux.Diagnostics(output)
        diagnostics.accepted()
        emitter = threading.Thread(target=diagnostics.emit)
        emitter.start()
        counter = None
        try:
            self.assertTrue(entered.wait(1))
            def count():
                diagnostics.accepted()
                diagnostics.record("capacity_rejected")
                diagnostics.closed()
                counted.set()
            counter = threading.Thread(target=count)
            counter.start()
            self.assertTrue(counted.wait(0.3))
        finally:
            release.set()
            emitter.join(timeout=1)
            if counter is not None:
                counter.join(timeout=1)

    def test_concurrent_events_and_periodic_report_are_bounded(self):
        output = []
        diagnostics = mux.Diagnostics(output.append)
        def count():
            for _ in range(100):
                diagnostics.record("capacity_rejected")
        workers = [threading.Thread(target=count) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=1)
        stop = Mock()
        stop.wait.side_effect = [False, False, True]
        diagnostics.report_forever(stop)
        self.assertEqual([call.args for call in stop.wait.call_args_list], [(30.0,)] * 3)
        self.assertEqual(len(output), 1)  # Second unchanged interval is silent.
        self.assertEqual(json.loads(output[0])["capacity_rejected"], 800)

    def test_handler_reports_only_fixed_failure_stage(self):
        cases = (("hello", mux.RejectedHello, "hello_rejected"),
                 ("hello", TimeoutError, "hello_timeout"),
                 ("connect", OSError, "upstream_connect_error"),
                 ("write", OSError, "upstream_write_error"),
                 ("relay", OSError, "relay_error"))
        for stage, error, expected in cases:
            with self.subTest(stage=stage, expected=expected):
                output = []
                diagnostics = mux.Diagnostics(output.append)
                client, upstream = Mock(), Mock()
                with patch.object(mux, "read_client_hello", return_value=(b"TLS", PUBLIC_HOST)) as hello, \
                        patch.object(mux.socket, "create_connection", return_value=upstream) as connect, \
                        patch.object(mux, "proxy_header", return_value=b"PROXY"), patch.object(mux, "pipe") as relay:
                    {"hello": hello, "connect": connect, "write": upstream.sendall, "relay": relay}[stage].side_effect = error("PRIVATE_EXCEPTION_PAYLOAD")
                    mux.handle(client, PUBLIC_HOST, CONNECT_HOST, diagnostics=diagnostics)
                diagnostics.emit()
                report = json.loads(output[0])
                self.assertEqual(report[expected], 1)
                self.assertEqual(sum(report[key] for key in mux.DIAGNOSTIC_CATEGORIES), 1)
                self.assertNotIn("PRIVATE_EXCEPTION_PAYLOAD", output[0])
                client.close.assert_called_once()

    def test_capacity_rejections_are_counted_without_opening_an_upstream(self):
        output = []
        diagnostics = mux.Diagnostics(output.append)
        listener, first, excess = MagicMock(), Mock(), Mock()
        listener.__enter__.return_value = listener
        listener.accept.side_effect = [(first, None), (excess, None), OSError("stop fixture")]
        with patch.dict(os.environ, {"PUBLIC_HOST": PUBLIC_HOST, "CONNECT_HOST": CONNECT_HOST, "FRONTDOOR_DIAGNOSTICS": "1"}), \
                patch.object(mux, "MAX_CONNECTIONS", 1), patch.object(mux, "CAPACITY_WAIT", 0), \
                patch.object(mux, "Diagnostics", return_value=diagnostics), \
                patch.object(mux.socket, "socket", return_value=listener), patch.object(mux.threading, "Thread"), \
                patch.object(mux.socket, "create_connection") as upstream:
            # Workers do not start, keeping the one permitted slot occupied.
            with self.assertRaises(OSError):
                mux.main()
        diagnostics.emit()
        report = json.loads(output[0])
        self.assertEqual((report["accepted"], report["capacity_rejected"], report["active_peak"]), (1, 1, 1))
        excess.close.assert_called_once()
        upstream.assert_not_called()

    def test_idle_relay_counter_does_not_include_socket_identity(self):
        output = []
        diagnostics = mux.Diagnostics(output.append)
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        try:
            mux.pipe(b, c, idle_timeout=0.01, diagnostics=diagnostics)
            diagnostics.emit()
            self.assertEqual(json.loads(output[0])["relay_idle_timeout"], 1)
        finally:
            for sock in (a, b, c, d):
                sock.close()

    def test_diagnostics_are_disabled_without_explicit_opt_in(self):
        listener = MagicMock()
        listener.__enter__.return_value = listener
        listener.accept.side_effect = OSError("stop fixture")
        with patch.dict(os.environ, {"PUBLIC_HOST": PUBLIC_HOST, "CONNECT_HOST": CONNECT_HOST, "FRONTDOOR_DIAGNOSTICS": "0"}), \
                patch.object(mux.socket, "socket", return_value=listener), patch.object(mux, "Diagnostics") as diagnostics, \
                patch.object(mux.threading, "Thread") as thread:
            with self.assertRaises(OSError):
                mux.main()
        diagnostics.assert_not_called()
        thread.assert_not_called()


class FrontdoorTests(unittest.TestCase):
    def test_real_client_hello_domain(self):
        hello = client_hello()
        wire, host = read_wire(hello)
        self.assertEqual(wire, hello)
        self.assertEqual(host, PUBLIC_HOST)
        self.assertEqual(mux.choose_upstream(host, PUBLIC_HOST, CONNECT_HOST), mux.CADDY)

    def test_no_sni_and_ip_sni_go_to_gateway(self):
        for host in (None, CONNECT_HOST):
            _, parsed = read_wire(client_hello(host))
            self.assertIsNone(parsed)  # OpenSSL suppresses the SNI extension for IPs.
            self.assertEqual(mux.choose_upstream(parsed, PUBLIC_HOST, CONNECT_HOST), mux.GATEWAY)
        hello = client_hello("aaa.aaa.aaa").replace(b"aaa.aaa.aaa", CONNECT_HOST.encode())
        _, parsed = read_wire(hello)
        self.assertEqual(parsed, CONNECT_HOST)
        self.assertEqual(mux.choose_upstream(parsed, PUBLIC_HOST, CONNECT_HOST), mux.GATEWAY)

    def test_unknown_sni_rejected(self):
        _, host = read_wire(client_hello("unknown.example.com"))
        with self.assertRaises(mux.RejectedHello):
            mux.choose_upstream(host, PUBLIC_HOST, CONNECT_HOST)
        with self.assertRaises(mux.RejectedHello):
            mux.choose_upstream("203.0.113.2", PUBLIC_HOST, CONNECT_HOST)

    def test_case_insensitive_sni(self):
        _, host = read_wire(client_hello("GATEWAY.EXAMPLE.COM"))
        self.assertEqual(host, PUBLIC_HOST)

    def test_handshake_fragmented_across_records(self):
        payload = client_hello()[5:]
        # Include fragmentation inside the four-byte handshake header.
        fragments = (payload[:1], payload[1:3], payload[3:70], payload[70:])
        wire = b"".join(record(part) for part in fragments)
        self.assertEqual(read_wire(wire), (wire, PUBLIC_HOST))

    def test_records_fragmented_across_tcp_reads(self):
        hello = client_hello()
        a, b = socket.socketpair()
        errors = []

        def sender():
            try:
                for index in range(0, len(hello), 3):
                    a.sendall(hello[index:index + 3])
                a.shutdown(socket.SHUT_WR)
            except OSError as error:
                errors.append(error)

        worker = threading.Thread(target=sender)
        worker.start()
        try:
            self.assertEqual(mux.read_client_hello(b), (hello, PUBLIC_HOST))
        finally:
            worker.join(timeout=2)
            a.close()
            b.close()
        self.assertFalse(errors)

    def test_plaintext_connect_and_proxy_preface_rejected(self):
        for data in (b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", b"PROXY TCP4 1.2.3.4 5.6.7.8 123 443\r\n"):
            with self.subTest(data=data[:7]), self.assertRaises(mux.RejectedHello):
                read_wire(data)

    def test_truncated_hello_and_records_rejected(self):
        hello = client_hello()
        for data in (b"", hello[:1], hello[:4], hello[:10], hello[:-1], record(hello[5:10])):
            with self.subTest(length=len(data)), self.assertRaises(mux.RejectedHello):
                read_wire(data)

    def test_record_type_and_lengths_rejected(self):
        for data in (b"\x17\x03\x03\x00\x01x", b"\x16\x03\x03\x00\x00", b"\x16\x03\x03\xff\xff", record(b"\x02\x00\x00\x00")):
            with self.subTest(data=data), self.assertRaises(mux.RejectedHello):
                read_wire(data)

    def test_client_hello_size_and_total_wire_cap(self):
        with self.assertRaises(mux.RejectedHello):
            read_wire(record(b"\x01\xff\xff\xff"))
        # Tiny records cannot evade the total 64 KiB cap with framing overhead.
        data = record(b"\x01\x00\xff\x00") + record(b"x") * 11000
        with self.assertRaises(mux.RejectedHello):
            read_wire(data)

    def test_extension_length_and_sni_boundaries_rejected(self):
        hello = client_hello()
        body = bytearray(hello[9:])
        # Session ID, cipher list and compression lead to the extension length.
        pos = 35 + body[34]
        pos += 2 + int.from_bytes(body[pos:pos + 2], "big")
        pos += 1 + body[pos]
        broken = body[:]
        broken[pos:pos + 2] = b"\xff\xff"
        with self.assertRaises(mux.RejectedHello):
            mux.parse_client_hello(bytes(broken))
        sni_pos = pos + 2
        while body[sni_pos:sni_pos + 2] != b"\x00\x00":
            sni_pos += 4 + int.from_bytes(body[sni_pos + 2:sni_pos + 4], "big")
        body[sni_pos + 4:sni_pos + 6] = b"\xff\xff"
        with self.assertRaises(mux.RejectedHello):
            mux.parse_client_hello(bytes(body))

    def test_absolute_deadline_is_not_reset_per_read(self):
        hello = client_hello()
        a, b = socket.socketpair()
        stop = threading.Event()

        def trickle():
            try:
                for byte in hello:
                    if stop.wait(0.01):
                        break
                    a.sendall(bytes([byte]))
            except OSError:
                pass

        sender = threading.Thread(target=trickle)
        sender.start()
        start = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                mux.read_client_hello(b, timeout=0.06)
            self.assertLess(time.monotonic() - start, 0.3)
        finally:
            stop.set()
            sender.join(timeout=1)
            a.close()
            b.close()

    def run_handler(self, hello):
        upstream = Upstream()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname()) as remote:
                accepted, peer = listener.accept()
                local = accepted.getsockname()
                remote.sendall(hello)
                remote.shutdown(socket.SHUT_WR)
                with patch.object(mux.socket, "create_connection", return_value=upstream) as connect, patch.object(mux, "pipe"):
                    mux.handle(accepted, PUBLIC_HOST, CONNECT_HOST)
                return upstream, connect.call_args, peer, local

    def test_caddy_gets_original_socket_peer_proxy_header(self):
        hello = client_hello()
        upstream, call, peer, local = self.run_handler(hello)
        expected = f"PROXY TCP4 {peer[0]} {local[0]} {peer[1]} {local[1]}\r\n".encode()
        self.assertEqual(upstream.sent, expected + hello)
        self.assertEqual(call.args[0], mux.CADDY)
        self.assertTrue(upstream.closed)

    def test_gateway_gets_untouched_tls_without_proxy_header(self):
        hello = client_hello(None)
        upstream, call, _, _ = self.run_handler(hello)
        self.assertEqual(upstream.sent, hello)
        self.assertEqual(call.args[0], mux.GATEWAY)

    def test_unknown_and_plaintext_never_open_upstream(self):
        for hello in (client_hello("unknown.example.com"), b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"):
            upstream, call, _, _ = self.run_handler(hello)
            self.assertIsNone(call)
            self.assertFalse(upstream.sent)

    def test_pipe_idle_timeout(self):
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        try:
            start = time.monotonic()
            mux.pipe(b, c, idle_timeout=0.03)
            self.assertLess(time.monotonic() - start, 0.3)
        finally:
            for sock in (a, b, c, d):
                sock.close()

    def test_active_upload_and_response_can_outlive_idle_timeout(self):
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        errors = []
        idle_timeout = 0.3

        def relay():
            try:
                mux.pipe(b, c, idle_timeout=idle_timeout)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=relay)
        worker.start()
        a.settimeout(1)
        d.settimeout(1)
        try:
            # Each unidirectional phase lasts longer than the idle timeout:
            # uploads and streamed responses must not have a total-time limit.
            for sender, receiver in ((a, d), (d, a)):
                start = time.monotonic()
                for _ in range(10):
                    sender.sendall(b"x")
                    self.assertEqual(receiver.recv(1), b"x")
                    time.sleep(0.04)
                self.assertGreater(time.monotonic() - start, idle_timeout)
                self.assertTrue(worker.is_alive())
            a.shutdown(socket.SHUT_WR)
            d.shutdown(socket.SHUT_WR)
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
            self.assertFalse(errors)
        finally:
            for sock in (a, b, c, d):
                sock.close()
            worker.join(timeout=1)

    def test_pipe_relays_both_directions_and_half_close(self):
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        errors = []

        def relay():
            try:
                mux.pipe(b, c, idle_timeout=1)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=relay)
        worker.start()
        try:
            a.sendall(b"request")
            a.shutdown(socket.SHUT_WR)
            d.settimeout(1)
            self.assertEqual(d.recv(7), b"request")
            self.assertEqual(d.recv(1), b"")
            d.sendall(b"response")
            d.shutdown(socket.SHUT_WR)
            a.settimeout(1)
            self.assertEqual(a.recv(8), b"response")
            self.assertEqual(a.recv(1), b"")
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(errors)
        finally:
            for sock in (a, b, c, d):
                sock.close()


if __name__ == "__main__":
    unittest.main()
