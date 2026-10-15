#!/usr/bin/env python3
"""Bounded TLS-only SNI front door. Never terminates or logs client traffic."""
import ipaddress
import os
import select
import socket
import threading
import time

MAX_HELLO_BYTES = 65536
HELLO_TIMEOUT = 10.0
CONNECT_TIMEOUT = 5.0
IDLE_TIMEOUT = 60.0
MAX_CONNECTIONS = 128
BUFFER_SIZE = 65536
CADDY = ("caddy", 443)
GATEWAY = ("gateway", 8443)


class RejectedHello(ValueError):
    pass


def _take(data, pos, size):
    if size < 0 or pos + size > len(data):
        raise RejectedHello("truncated ClientHello")
    return data[pos:pos + size], pos + size


def parse_client_hello(body):
    """Return the one ASCII host_name, or None when SNI is absent."""
    version, pos = _take(body, 0, 2)
    if version not in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
        raise RejectedHello("invalid legacy TLS version")
    _, pos = _take(body, pos, 32)
    raw, pos = _take(body, pos, 1)
    if raw[0] > 32:
        raise RejectedHello("invalid session ID")
    _, pos = _take(body, pos, raw[0])
    raw, pos = _take(body, pos, 2)
    size = int.from_bytes(raw, "big")
    if size < 2 or size % 2:
        raise RejectedHello("invalid cipher suites")
    _, pos = _take(body, pos, size)
    raw, pos = _take(body, pos, 1)
    if not raw[0]:
        raise RejectedHello("missing compression methods")
    _, pos = _take(body, pos, raw[0])
    if pos == len(body):
        return None
    raw, pos = _take(body, pos, 2)
    if int.from_bytes(raw, "big") != len(body) - pos:
        raise RejectedHello("invalid extensions length")
    seen = set()
    hostname = None
    while pos < len(body):
        raw, pos = _take(body, pos, 4)
        kind, size = int.from_bytes(raw[:2], "big"), int.from_bytes(raw[2:], "big")
        if kind in seen:
            raise RejectedHello("duplicate extension")
        seen.add(kind)
        extension, pos = _take(body, pos, size)
        if kind != 0:
            continue
        raw, name_pos = _take(extension, 0, 2)
        if int.from_bytes(raw, "big") != len(extension) - name_pos:
            raise RejectedHello("invalid SNI length")
        if name_pos == len(extension):
            raise RejectedHello("empty SNI")
        name_types = set()
        while name_pos < len(extension):
            raw, name_pos = _take(extension, name_pos, 3)
            name_type, name_size = raw[0], int.from_bytes(raw[1:], "big")
            if name_type in name_types:
                raise RejectedHello("duplicate SNI name type")
            name_types.add(name_type)
            name, name_pos = _take(extension, name_pos, name_size)
            if name_type == 0:
                try:
                    hostname = name.decode("ascii").lower()
                except UnicodeError as exc:
                    raise RejectedHello("non-ASCII SNI") from exc
                if not hostname or any(c <= " " or c >= "\x7f" for c in hostname):
                    raise RejectedHello("invalid SNI name")
        if hostname is None:
            raise RejectedHello("missing SNI host_name")
    return hostname


def read_client_hello(client, timeout=HELLO_TIMEOUT):
    """Read complete handshake records under one deadline and a total wire cap."""
    deadline = time.monotonic() + timeout
    wire = bytearray()
    handshake = bytearray()

    def read_exact(size):
        if len(wire) + size > MAX_HELLO_BYTES:
            raise RejectedHello("ClientHello too large")
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("ClientHello deadline")
            client.settimeout(remaining)
            chunk = client.recv(size - len(result))
            if not chunk:
                raise RejectedHello("truncated TLS record")
            if time.monotonic() > deadline:
                raise TimeoutError("ClientHello deadline")
            result.extend(chunk)
            wire.extend(chunk)
        return bytes(result)

    while True:
        header = read_exact(5)
        if header[0] != 22 or header[1] != 3 or header[2] not in (1, 2, 3):
            raise RejectedHello("TLS handshake required")
        size = int.from_bytes(header[3:], "big")
        if not 0 < size <= 18432:
            raise RejectedHello("invalid TLS record length")
        handshake.extend(read_exact(size))
        if handshake and handshake[0] != 1:
            raise RejectedHello("ClientHello required")
        if len(handshake) < 4:
            continue
        hello_size = 4 + int.from_bytes(handshake[1:4], "big")
        if hello_size > MAX_HELLO_BYTES - 5:
            raise RejectedHello("ClientHello too large")
        if len(handshake) >= hello_size:
            return bytes(wire), parse_client_hello(handshake[4:hello_size])


def choose_upstream(hostname, public_host, connect_host):
    if hostname is None:
        return GATEWAY
    if hostname == public_host:
        return CADDY
    try:
        if ipaddress.ip_address(hostname) == ipaddress.ip_address(connect_host):
            return GATEWAY
    except ValueError:
        pass
    raise RejectedHello("unknown SNI")


def proxy_header(client):
    """Use kernel socket addresses exclusively; client bytes cannot set identity."""
    peer, local = client.getpeername(), client.getsockname()
    source, destination = ipaddress.ip_address(peer[0]), ipaddress.ip_address(local[0])
    if source.version != destination.version:
        raise ValueError("mixed socket address families")
    return (f"PROXY TCP{source.version} {source} {destination} {peer[1]} {local[1]}\r\n").encode("ascii")


def pipe(client, upstream, idle_timeout=IDLE_TIMEOUT):
    """Relay with bounded per-direction buffers, half-closes and an idle timeout."""
    sockets = (client, upstream)
    pending = {client: bytearray(), upstream: bytearray()}
    reading = set(sockets)
    shut = set()
    for sock in sockets:
        sock.setblocking(False)
    last_activity = time.monotonic()
    while True:
        for src, dst in ((client, upstream), (upstream, client)):
            if src not in reading and not pending[dst] and dst not in shut:
                dst.shutdown(socket.SHUT_WR)
                shut.add(dst)
        if not reading and not any(pending.values()):
            return
        remaining = idle_timeout - (time.monotonic() - last_activity)
        if remaining <= 0:
            return
        readers = [s for s in reading if len(pending[upstream if s is client else client]) < BUFFER_SIZE]
        writers = [s for s in sockets if pending[s]]
        ready_read, ready_write, _ = select.select(readers, writers, [], remaining)
        if not ready_read and not ready_write:
            return
        for src in ready_read:
            dst = upstream if src is client else client
            try:
                data = src.recv(min(16384, BUFFER_SIZE - len(pending[dst])))
            except BlockingIOError:
                continue
            if data:
                pending[dst].extend(data)
                last_activity = time.monotonic()
            else:
                reading.remove(src)
        for dst in ready_write:
            try:
                count = dst.send(pending[dst])
            except BlockingIOError:
                continue
            if count <= 0:
                return
            del pending[dst][:count]
            last_activity = time.monotonic()


def handle(client, public_host, connect_host):
    upstream = None
    try:
        hello, hostname = read_client_hello(client)
        target = choose_upstream(hostname, public_host, connect_host)
        upstream = socket.create_connection(target, CONNECT_TIMEOUT)
        if target == CADDY:
            upstream.sendall(proxy_header(client))
        upstream.sendall(hello)
        pipe(client, upstream)
    except (OSError, ValueError):
        # Do not log client traffic, SNI, URLs, or tunnel credentials.
        pass
    finally:
        for sock in (client, upstream):
            if sock is not None:
                sock.close()


def main():
    public_host = os.environ["PUBLIC_HOST"].lower()
    connect_host = str(ipaddress.ip_address(os.environ["CONNECT_HOST"]))
    if not public_host or public_host == connect_host:
        raise ValueError("PUBLIC_HOST must be the gateway DNS name")
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def worker(client):
        try:
            handle(client, public_host, connect_host)
        finally:
            slots.release()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 443))
        server.listen(MAX_CONNECTIONS)
        while True:
            client, _ = server.accept()
            if not slots.acquire(blocking=False):
                client.close()
                continue
            try:
                threading.Thread(target=worker, args=(client,), daemon=True).start()
            except RuntimeError:
                slots.release()
                client.close()


if __name__ == "__main__":
    main()
