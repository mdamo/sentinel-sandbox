"""Host-owned, confined effects for approved actions.

Network sends are recorded in a local outbox; this adapter has no outbound
socket. It deliberately does not run agent-supplied programs.
"""

from __future__ import annotations

import json
from pathlib import Path

from .actions import Action, ActionType


class EffectError(ValueError):
    pass


class EffectAdapter:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve(strict=True)
        self.work = self.root / "work"
        self.secrets = self.root / "secrets"
        self.work.mkdir(exist_ok=True)
        (self.work / "tmp").mkdir(exist_ok=True)
        self.outbox = self.root / "outbox.jsonl"
        self.bus = self.root / "bus.jsonl"

    def _path(self, raw: object, *, write: bool = False) -> Path:
        if not isinstance(raw, str) or not raw.startswith(("/work/", "/secrets/")):
            raise EffectError("invalid path")
        relative = Path(raw.lstrip("/"))
        if ".." in relative.parts:
            raise EffectError("parent traversal is forbidden")
        path = (self.root / relative).resolve()
        if not (path.is_relative_to(self.work) or path.is_relative_to(self.secrets)):
            raise EffectError("path escapes effect root")
        if write and not path.is_relative_to(self.work / "tmp"):
            raise EffectError("write escapes scratch area")
        return path

    def perform(self, action: Action) -> dict:
        p = action.params
        if action.type == ActionType.FILE_READ:
            data = self._path(p.get("path")).read_bytes()
            if len(data) > 65536:
                raise EffectError("read exceeds 64 KiB")
            return {"content": data.decode("utf-8")}
        if action.type == ActionType.FILE_WRITE:
            path = self._path(p.get("path"), write=True)
            payload = p.get("payload", "")
            if not isinstance(payload, str) or len(payload.encode()) > 65536:
                raise EffectError("invalid write payload")
            path.write_text(payload)
            return {"bytes_written": len(payload.encode())}
        if action.type == ActionType.NET_SEND:
            self._append(self.outbox, action)
            return {"recorded": True}
        if action.type == ActionType.BUS_PUBLISH:
            self._append(self.bus, action)
            return {"recorded": True}
        if action.type == ActionType.DNS_RESOLVE:
            return {"host": p["host"], "address": "127.0.0.1"}
        raise EffectError("no trusted adapter for this action type")

    @staticmethod
    def _append(path: Path, action: Action) -> None:
        payload = json.dumps({"agent_id": action.agent_id, "params": action.params})
        with path.open("a", encoding="utf-8") as stream:
            stream.write(payload + "\n")
