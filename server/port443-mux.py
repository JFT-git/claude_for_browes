#!/usr/bin/env python3
"""Share public port 443 between Caddy (TLS) and the artifact CONNECT proxy.

Cloudflare does not forward CONNECT, and the cloud firewall only exposes 443,
so plaintext CONNECT for artifact hosts arrives on the same port as HTTPS.
TLS (first byte 0x16) goes to Caddy. Anything else goes to the CONNECT proxy.
"""
import select
import socket
import threading

TLS = ("127.0.0.1", 4443)
PROXY = ("127.0.0.1", 8888)


def pipe(a, b):
    try:
        while True:
            ready, _, _ = select.select([a, b], [], [], 600)
            if not ready:
                return
            for src in ready:
                data = src.recv(65536)
                if not data:
                    return
                (b if src is a else a).sendall(data)
    except Exception:
        pass
    finally:
        for sock in (a, b):
            try:
                sock.close()
            except Exception:
                pass


def handle(client):
    upstream = None
    try:
        client.settimeout(15)
        first = client.recv(1)
        if not first:
            client.close()
            return
        upstream = socket.create_connection(TLS if first == b"\x16" else PROXY, 10)
        upstream.sendall(first)
        client.settimeout(None)
        upstream.settimeout(None)
        pipe(client, upstream)
    except Exception:
        for sock in (client, upstream):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen(256)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
