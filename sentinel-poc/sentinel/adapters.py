"""Narrow Linux file and pinned-address HTTP adapters; no arbitrary execution."""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
import stat
import time
import threading
import multiprocessing
from dataclasses import dataclass

from .actions import ActionType


def _resolve_worker(connection, host, port):
    try:
        connection.send(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    except Exception:
        connection.send(None)
    finally:
        connection.close()


class Rejected(ValueError):
    def __init__(self, rule: str):
        super().__init__(rule)
        self.rule = rule


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int = 443
    scheme: str = "https"
    method: str = "POST"
    route: str = "/result"
    allowed_ips: tuple[str, ...] = ()
    max_payload: int = 16384
    max_response: int = 16384
    response_sensitive: bool = True
    ca_file: str | None = None

    def __post_init__(self):
        if (self.scheme not in {"http", "https"} or self.method != "POST"
                or not 1 <= self.port <= 65535 or not self.route.startswith("/")
                or any(c in self.host + self.route for c in "\r\n\x00")
                or not self.host.isascii() or not self.route.isascii()
                or any(c in self.host for c in "/ @?#\\")
                or any(c in self.route for c in " ?#\\")
                or self.max_payload < 0 or self.max_response < 0):
            raise ValueError("invalid endpoint")
        for address in self.allowed_ips:
            ipaddress.ip_address(address)
        if self.scheme == "http" and (not self.allowed_ips or
                not all(ipaddress.ip_address(x).is_loopback for x in self.allowed_ips)):
            raise ValueError("plaintext HTTP only permitted for explicitly pinned loopback fixtures")


class Adapters:
    def __init__(self, workspace: str, endpoints: dict[str, Endpoint], max_file=65536, timeout=5):
        self.root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.endpoints = dict(endpoints)
        self.max_file = max_file
        self.timeout = timeout

    def validate(self, kind: ActionType, params: dict) -> dict:
        """Pure shape/scope preparation. No DNS or requested effect occurs here."""
        p = dict(params)
        if kind in {ActionType.FILE_READ, ActionType.FILE_WRITE}:
            allowed = {"path"} if kind == ActionType.FILE_READ else {"path", "payload"}
            if set(p) - allowed or not isinstance(p.get("path"), str):
                raise Rejected("request-shape")
            parts = p["path"].split("/")
            if not parts or any(x in {"", ".", ".."} or "\x00" in x for x in parts):
                raise Rejected("fs-path")
            if kind == ActionType.FILE_WRITE and (not isinstance(p.get("payload"), str)
                    or len(p["payload"].encode()) > self.max_file):
                raise Rejected("payload-limit")
        elif kind == ActionType.NET_SEND:
            if set(p) - {"endpoint", "payload"} or not isinstance(p.get("payload"), str):
                raise Rejected("request-shape")
            e = self.endpoint(p)
            if len(p["payload"].encode()) > e.max_payload:
                raise Rejected("payload-limit")
        elif kind == ActionType.DNS_RESOLVE:
            if set(p) != {"endpoint"}:
                raise Rejected("request-shape")
            self.endpoint(p)
        elif kind == ActionType.BUS_PUBLISH:
            if set(p) != {"recipient", "topic", "payload"} or not all(isinstance(x, str) for x in p.values()):
                raise Rejected("request-shape")
            if len(p["payload"].encode()) > self.max_file:
                raise Rejected("payload-limit")
        else:
            raise Rejected("execution-disabled")
        return p

    def endpoint(self, params):
        name = params.get("endpoint")
        if not isinstance(name, str) or name not in self.endpoints:
            raise Rejected("endpoint-scope")
        return self.endpoints[name]

    def wire(self, params):
        e = self.endpoint(params)
        payload = params["payload"].encode()
        host = f"[{e.host}]" if ":" in e.host else e.host
        headers = (f"{e.method} {e.route} HTTP/1.1\r\nHost: {host}:{e.port}\r\n"
                   f"Content-Type: text/plain; charset=utf-8\r\nContent-Length: {len(payload)}\r\n"
                   "Connection: close\r\n\r\n").encode("ascii")
        return headers + payload

    def addresses(self, e):
        # Resolve once, validate EVERY answer, and connect to an already checked address.
        # A spawned helper bounds libc resolver hangs without leaving blocked threads.
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_resolve_worker, args=(child, e.host, e.port))
        try:
            process.start()
            child.close()
            if not parent.poll(self.timeout):
                raise TimeoutError("DNS deadline")
            rows = parent.recv()
        finally:
            parent.close()
            child.close()
            if process.pid:
                if process.is_alive():
                    process.terminate()
                process.join()
        if not rows:
            raise Rejected("resolved-address")
        for _, _, _, _, addr in rows:
            ip = ipaddress.ip_address(addr[0])
            if ip.is_unspecified or ip.is_multicast or (e.allowed_ips and str(ip) not in e.allowed_ips):
                raise Rejected("resolved-address")
            if not ip.is_global and str(ip) not in e.allowed_ips:
                raise Rejected("resolved-address")
        return rows

    def file(self, kind, p):
        parts = p["path"].split("/")
        directory = os.dup(self.root)
        try:
            for component in parts[:-1]:
                new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory)
                os.close(directory)
                directory = new
            flags = os.O_NOFOLLOW | os.O_NONBLOCK
            if kind == ActionType.FILE_READ:
                flags |= os.O_RDONLY
            else:
                # Create-only: never truncate an existing file or follow a hardlink.
                flags |= os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(parts[-1], flags, 0o600, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise Rejected("fs-object")
                if kind == ActionType.FILE_READ:
                    if info.st_size > self.max_file:
                        raise Rejected("file-limit")
                    chunks, size = [], 0
                    while True:
                        chunk = os.read(fd, min(8192, self.max_file + 1 - size))
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > self.max_file:
                            raise Rejected("file-limit")
                        chunks.append(chunk)
                    return {"data": b"".join(chunks).decode("utf-8"), "bytes": size}
                raw, total = p["payload"].encode(), 0
                while total < len(raw):
                    total += os.write(fd, raw[total:])
                os.fsync(fd)
                os.fsync(directory)
                return {"bytes": total}
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def perform(self, kind, params):
        if kind in {ActionType.FILE_READ, ActionType.FILE_WRITE}:
            return self.file(kind, params)
        e = self.endpoint(params)
        rows = self.addresses(e)
        if kind == ActionType.DNS_RESOLVE:
            return {"addresses": sorted({r[4][0] for r in rows}), "wire_bytes": 0}
        family, socktype, proto, _, address = rows[0]
        deadline = time.monotonic() + self.timeout
        sock = socket.socket(family, socktype, proto)
        def abort():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(self.timeout, abort)
        timer.daemon = True
        timer.start()
        try:
            sock.settimeout(self.timeout)
            sock.connect(address)
            if e.scheme == "https":
                sock = ssl.create_default_context(cafile=e.ca_file).wrap_socket(sock, server_hostname=e.host)
            raw = self.wire(params)
            sock.sendall(raw)
            response = http.client.HTTPResponse(sock)
            response.begin()
            if 300 <= response.status < 400:
                raise Rejected("redirect-disabled")
            data = bytearray()
            while len(data) <= e.max_response:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP deadline")
                sock.settimeout(remaining)
                part = response.read1(min(8192, e.max_response + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            if len(data) > e.max_response:
                raise Rejected("response-limit")
            return {"status": response.status, "data": data.decode("utf-8"), "wire_bytes": len(raw)}
        finally:
            timer.cancel()
            sock.close()

    def close(self):
        os.close(self.root)
