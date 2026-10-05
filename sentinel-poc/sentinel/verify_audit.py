"""Offline verification against an independently retained signed checkpoint."""
import argparse
import json
from pathlib import Path

from .storage import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--key-file", required=True, help="private file containing audit key as hex")
    args = parser.parse_args()
    checkpoint = json.loads(Path(args.checkpoint).read_text())
    checkpoint = checkpoint.get("checkpoint", checkpoint)
    key = bytes.fromhex(Path(args.key_file).read_text().strip())
    store = Store(args.database)
    try:
        store.verify_checkpoint(checkpoint, key)
        print("Audit chain, state digest, and retained checkpoint verified.")
    finally:
        store.close()


if __name__ == "__main__":
    main()
