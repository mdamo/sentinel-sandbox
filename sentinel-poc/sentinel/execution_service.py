"""Opt-in execution service: protected Unix socket or TLS, never plain TCP auth."""
from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .actions import ActionType
from .adapters import Adapters, Endpoint, Rejected
from .monitor import Budget
from .policy import Capability, Policy
from .runtime import Identity, Runtime
from .storage import Store


def load_runtime(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as source:
        if os.fstat(source.fileno()).st_mode & 0o077:
            raise ValueError("configuration contains secrets; require mode 0600")
        c = json.load(source)
    policy = Policy(sensitive_prefixes=tuple(c.get("sensitive_paths", [])),
                    canary_paths=frozenset(c.get("canary_paths", [])))
    for agent, cap in c["agents"].items():
        policy.grant(agent, Capability(
            frozenset(ActionType(x) for x in cap["types"]),
            frozenset(cap.get("hosts", [])), frozenset(),
            tuple(cap.get("read", [])), tuple(cap.get("write", []))))
    credentials = {token: Identity(**identity) for token, identity in c["credentials"].items()}
    for directory in (c["workspace"], os.path.dirname(os.path.abspath(c["database"]))):
        info = os.stat(directory, follow_symlinks=False)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("workspace and database parent must be service-owned with mode 0700")
    adapter = Adapters(c["workspace"], {k: Endpoint(**v) for k, v in c.get("endpoints", {}).items()},
                       max_file=c.get("max_file", 65536), timeout=c.get("timeout", 5))
    try:
        store = Store(c["database"])
        try:
            return Runtime(policy, adapter, store, credentials, swarm=c["swarm"], run=c["run"],
                policy_version=c["policy_version"], audit_key=bytes.fromhex(c["audit_key_hex"]),
                per_agent=Budget(**c["per_agent"]), per_swarm=Budget(**c["per_swarm"]),
                share_pairs=frozenset(tuple(x) for x in c.get("share_pairs", [])),
                topics=frozenset(c.get("topics", [])),
                endpoint_grants={k: frozenset(v.get("endpoints", [])) for k, v in c["agents"].items()},
                max_agent_admissions=c.get('max_agent_admissions', 1024),
                max_run_admissions=c.get('max_run_admissions', 4096),
                workflow_hosts=frozenset(c.get("workflow_hosts", [])))
        except BaseException:
            store.close()
            raise
    except BaseException:
        adapter.close()
        raise


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        # Start before BaseHTTPRequestHandler reads the request line or headers.
        # An absolute deadline also stops clients that drip bytes indefinitely.
        timeout = self.server.request_timeout
        self.connection.settimeout(timeout)
        def expire():
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.read_deadline = threading.Timer(timeout, expire)
        self.read_deadline.daemon = True
        self.read_deadline.start()
        try:
            super().handle()
        except OSError:
            pass  # timeout/disconnect; no request body or credentials in logs
        finally:
            self._finish_reading()

    def _finish_reading(self):
        self.read_deadline.cancel()
        self.read_deadline.join()

    def do_POST(self):
        status = 200
        try:
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise Rejected("request-framing")
            length = int(self.headers["Content-Length"])
            if not 0 < length <= 65536:
                raise Rejected("request-limit")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise Rejected("request-framing")
            self._finish_reading()
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise Rejected("request-shape")
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise Rejected("authentication")
            token = auth[7:]
            runtime = self.server.runtime
            if self.path == "/execute":
                out = runtime.execute(token, body)
            elif self.path == "/receive":
                out = runtime.receive(token, body["handle"])
            elif self.path == "/admin/resume":
                out = runtime.resume(token, body["reason"], body["incident"])
            elif self.path == "/admin/checkpoint":
                out = dict(allow=True, rule="checkpoint", checkpoint=runtime.checkpoint(token))
            else:
                status, out = 404, Runtime.denied("endpoint")
        except Rejected as exc:
            out = Runtime.denied(exc.rule)
        except Exception:
            out = Runtime.denied("request-invalid")
        payload = json.dumps(out).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def log_message(self, *_):
        pass  # durable redacted audit; never log Authorization/body/result


class BoundedThreads:
    """Bound handlers, including slow body readers and resolver subprocesses."""
    daemon_threads = False
    block_on_close = True
    request_timeout = 5

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class UnixServer(BoundedThreads, socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = False
    block_on_close = True
    server_name, server_port = "localhost", 0


class TLSServer(BoundedThreads, ThreadingHTTPServer):
    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.request_timeout)
        try:
            return self.context.wrap_socket(request, server_side=True,
                                            do_handshake_on_connect=False), address
        except BaseException:
            request.close()
            raise

    def finish_request(self, request, client_address):
        # Called in a bounded worker, never in the accept loop. SSL's timeout
        # bounds the complete handshake, including clients that send no bytes.
        try:
            request.do_handshake()
        except OSError:
            return
        super().finish_request(request, client_address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--unix")
    transport.add_argument("--tls-bind", help="HOST:PORT; certificate and key required")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    os.umask(0o077)
    runtime = load_runtime(args.config)
    server = None
    created = False
    try:
        if args.unix:
            # Never replace an existing socket; use a service-owned mode-0700 parent.
            parent = os.stat(os.path.dirname(os.path.abspath(args.unix)))
            if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise ValueError("Unix socket parent must be owned by service user with mode 0700")
            server = UnixServer(args.unix, Handler)
            created = True
            os.chmod(args.unix, 0o600)
        else:
            if not args.cert or not args.key:
                raise ValueError("TLS certificate and key required")
            host, port = args.tls_bind.rsplit(":", 1)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
            server = TLSServer((host, int(port)), Handler)
            server.context = context
        server.runtime = runtime
        print("sentinel execution service ready", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.server_close()
        runtime.close()
        if created:
            os.unlink(args.unix)


if __name__ == "__main__":
    main()
