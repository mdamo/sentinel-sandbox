"""Small client for the opt-in execution service; credentials read from private files."""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--unix")
    transport.add_argument("--https")
    parser.add_argument("--ca")
    parser.add_argument("--credential-file", required=True)
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--endpoint", default="/execute",
                        choices=["/execute", "/receive", "/admin/resume", "/admin/checkpoint"])
    parser.add_argument("--output", help="write result/checkpoint to a new private file")
    args = parser.parse_args()
    fd = os.open(args.credential_file, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as source:
        if os.fstat(source.fileno()).st_mode & 0o077:
            raise ValueError("credential file requires mode 0600")
        token = source.read(1024).strip()
    with open(args.request_file) as source:
        body = json.load(source)
    if args.unix:
        connection = http.client.HTTPConnection("localhost", timeout=15)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(15)
        connection.sock.connect(args.unix)
    else:
        url = urlsplit(args.https)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in {"", "/"}:
            raise ValueError("HTTPS origin required")
        connection = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=15,
                                                context=ssl.create_default_context(cafile=args.ca))
    try:
        connection.request("POST", args.endpoint, json.dumps(body),
                           {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError("response too large")
        result = json.loads(raw)
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as destination:
                json.dump(result, destination, indent=2)
                destination.write("\n")
        else:
            print(json.dumps(result, indent=2))
        raise SystemExit(0 if result.get("allow") else 1)
    finally:
        connection.close()


if __name__ == "__main__":
    main()
