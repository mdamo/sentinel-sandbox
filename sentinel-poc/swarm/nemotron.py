"""NVIDIA Nemotron proposal transport outside the deterministic sentinel."""
from __future__ import annotations

import json
import os
import logging
from pathlib import Path
import shlex
import urllib.error
import urllib.request

from .ai_agents import ToolCall
from .catalog import ROLE_TOOLS, tool_prompt, validate_arguments

DEFAULT_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"


def load_env(path: Path | None = None) -> None:
    """Load supported settings from the repository .env without shell execution."""
    path = path if path is not None else Path(__file__).resolve().parents[2] / ".env"
    if not path.is_file():
        return
    supported = {"NVIDIA_API_KEY", "NVIDIA_MODEL", "NVIDIA_BASE_URL",
                 "LOG_LEVEL"}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if key not in supported:
            continue
        try:
            tokens = shlex.split(value, comments=True)
            if not separator or len(tokens) > 1:
                raise ValueError
        except ValueError:
            raise ModelError(f"Invalid .env setting on line {number}") from None
        os.environ.setdefault(key, tokens[0] if tokens else "")


class ModelError(RuntimeError):
    """A transport or proposal error; no actions should be submitted."""


def parse_calls(content: str) -> list[ToolCall]:
    try:
        data = json.loads(content)
        if not isinstance(data, dict) or set(data) != {"calls"}:
            raise ValueError("expected an object containing only calls")
        calls = data["calls"]
        if not isinstance(calls, list) or not 1 <= len(calls) <= 6:
            raise ValueError("expected one to six calls")
        result = []
        for call in calls:
            if not isinstance(call, dict) or set(call) != {"name", "arguments"}:
                raise ValueError("each call needs name and arguments")
            args = call["arguments"]
            validate_arguments(call["name"], args)
            result.append(ToolCall(call["name"], args))
        return result
    except (ValueError, TypeError, KeyError) as exc:
        raise ModelError("Invalid model proposal; no actions submitted") from exc


class NemotronModel:
    """One bounded request per role, with no retries or provider fallback."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        load_env()
        self.provider = "NVIDIA"
        self._api_key = api_key or os.environ.get("NVIDIA_API_KEY", "")
        self.model = model or os.environ.get("NVIDIA_MODEL") or DEFAULT_MODEL
        if not self.model.startswith("nvidia/nemotron-"):
            raise ModelError("Choose an NVIDIA Nemotron model")
        base_url = os.environ.get("NVIDIA_BASE_URL") or "https://integrate.api.nvidia.com/v1"
        self.endpoint = base_url.rstrip("/") + "/chat/completions"
        if not self.endpoint.startswith("https://"):
            raise ModelError("NVIDIA_BASE_URL must use HTTPS")
        if not self._api_key.strip():
            raise ModelError("Set NVIDIA_API_KEY to use Nemotron")
        level = os.environ.get("LOG_LEVEL", "INFO").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ModelError("Invalid LOG_LEVEL")
        logging.basicConfig(level=level)

    def propose(self, role: str, task: str) -> list[ToolCall]:
        prompt = (
            "Propose abstract tool calls for a sandbox simulation. Do not execute anything. "
            "Return ONLY JSON: {\"calls\":[{\"name\":\"tool_name\",\"arguments\":{}}]}. "
            "Return one to six calls. All argument values must be strings. "
            f"Available tools: {tool_prompt()} "
            f"Role tool suggestions: {json.dumps(ROLE_TOOLS)}. "
            "Roles: researcher reads /work/input/task.json; writer writes /work/tmp/report; "
            "analyst proposes run_python; reporter sends to api.internal.svc; "
            "resolver resolves api.internal.svc; coordinator publishes a message. "
            "Choose tools appropriate to the requested role and task. "
            "run_python takes no arguments: use {\"name\":\"run_python\",\"arguments\":{}}. "
            "Do not generate Python code. Keep payload strings short. "
            "Only /work/ reads, /work/tmp/ writes, and api.internal.svc are appropriate. "
            "The sentinel independently decides permission."
        )
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": prompt},
                         {"role": "user", "content": json.dumps({"role": role, "task": task})}],
            "max_tokens": 2048,
            "temperature": 0,
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {"type": "json_object"},
        }).encode()
        request = urllib.request.Request(self.endpoint, data=body, headers={
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ModelError("Model response exceeded size limit")
            data = json.loads(raw)
            choice = data["choices"][0]
            if choice.get("finish_reason") != "stop":
                raise ModelError("Model response incomplete; no actions submitted")
            content = choice["message"]["content"]
            if not isinstance(content, str):
                raise ModelError("Model did not return text; no actions submitted")
            return parse_calls(content)
        except urllib.error.HTTPError as exc:
            raise ModelError(f"{self.provider} HTTP {exc.code}; no actions submitted") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ModelError(f"{self.provider} request failed; no actions submitted") from None
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelError(f"Malformed {self.provider} response; no actions submitted") from None
