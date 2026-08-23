"""Exercise Ventris's loopback HTTP security and protocol boundaries."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import sys
import time


MAX_HEADER = 16 * 1024
MAX_BODY = 4 * 1024 * 1024


def free_port(host: str) -> int:
    with socket.socket() as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


def request(host: str, port: int, payload: bytes) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=3) as connection:
            connection.sendall(payload)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = connection.recv(64 * 1024)
                except (ConnectionResetError, socket.timeout):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
    except (ConnectionResetError, BrokenPipeError):
        return b""


def status(response: bytes) -> int | None:
    line = response.split(b"\r\n", 1)[0]
    fields = line.split()
    if len(fields) < 2 or fields[0] != b"HTTP/1.1":
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def wait_for_health(host: str, port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    payload = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited with status {process.returncode}")
        if status(request(host, port, payload)) == 200:
            return
        time.sleep(0.05)
    raise RuntimeError("server did not become healthy")


def run(binary: Path, host: str, requested_port: int) -> None:
    port = requested_port or free_port(host)
    process = subprocess.Popen(
        [str(binary), "serve", "--bind", f"{host}:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_health(host, port, process)
        cases = {
            "health": (
                b"GET /health HTTP/1.1\r\nHost: localhost\r\n"
                b"Connection: close\r\n\r\n",
                200,
            ),
            "unsupported-method": (
                b"POST /health HTTP/1.1\r\nHost: localhost\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n",
                405,
            ),
            "unknown-path": (
                b"GET /not-an-endpoint HTTP/1.1\r\nHost: localhost\r\n"
                b"Connection: close\r\n\r\n",
                404,
            ),
            "malformed-query": (
                b"GET /inspect?format=invalid HTTP/1.1\r\nHost: localhost\r\n"
                b"Connection: close\r\n\r\n",
                400,
            ),
        }
        for name, (payload, expected) in cases.items():
            actual = status(request(host, port, payload))
            if actual != expected:
                raise RuntimeError(f"{name}: expected HTTP {expected}, got {actual}")

        oversized_body = (
            b"POST /batch HTTP/1.1\r\nHost: localhost\r\n"
            + f"Content-Length: {MAX_BODY + 1}\r\n".encode()
            + b"Connection: close\r\n\r\n"
        )
        if request(host, port, oversized_body):
            raise RuntimeError("oversized-body: server returned a response")

        oversized_header = (
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Fill: "
            + b"x" * MAX_HEADER
            + b"\r\nConnection: close\r\n\r\n"
        )
        if request(host, port, oversized_header):
            raise RuntimeError("oversized-header: server returned a response")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if not args.binary.is_file():
        print(f"http-smoke: FAIL native binary not found: {args.binary}", file=sys.stderr)
        return 1
    try:
        run(args.binary, args.host, args.port)
    except (OSError, RuntimeError) as error:
        print(f"http-smoke: FAIL {error}", file=sys.stderr)
        return 1
    print(f"http-smoke: PASS {args.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
