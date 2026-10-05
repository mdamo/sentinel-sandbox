"""Create a private local file-only configuration; never overwrite an existing run."""
import argparse
import json
import os
from pathlib import Path
import secrets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="new directory owned by the service account")
    args = parser.parse_args()
    os.umask(0o077)
    base = Path(args.directory).absolute()
    base.mkdir(mode=0o700)
    workspace = base / "workspace"
    workspace.mkdir(mode=0o700)
    for name in ("input", "output"):
        (workspace / name).mkdir(mode=0o700)
    (workspace / "input/task.txt").write_text("public task\n")
    run = secrets.token_hex(16)
    credentials = {}
    for name, admin in (("agent-1", False), ("operator", True)):
        token = secrets.token_urlsafe(48)
        credentials[token] = dict(name=name, swarm="local", run=run, admin=admin)
        (base / (name + ".token")).write_text(token + "\n")
    config = dict(workspace=str(workspace), database=str(base / "state.sqlite"),
        swarm="local", run=run, policy_version="local-file-v1", audit_key_hex=secrets.token_hex(32),
        agents={"agent-1": dict(types=["file_read", "file_write"], read=["input"], write=["output"], endpoints=[])},
        credentials=credentials, endpoints={}, sensitive_paths=[], canary_paths=[],
        per_agent=dict(max_bytes_out=100000, max_requests=100, max_distinct_dests=1),
        per_swarm=dict(max_bytes_out=100000, max_requests=100, max_distinct_dests=1),
        share_pairs=[], topics=[], workflow_hosts=[])
    (base / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (base / "read-request.json").write_text(json.dumps(dict(request_id="read-public-1", type="file_read",
                                                         params={"path": "input/task.txt"})) + "\n")
    print(f"Created private configuration: {base / 'config.json'}")
    print("Credential contents were not printed. Keep operator/config files outside the agent.")


if __name__ == "__main__":
    main()
