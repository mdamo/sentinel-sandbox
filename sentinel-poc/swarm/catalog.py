"""Shared six-agent roster and twenty tools with strict string arguments."""

from dataclasses import dataclass

AGENT_ROLES = {
    "agent-1": "researcher",
    "agent-2": "writer",
    "agent-3": "analyst",
    "agent-4": "reporter",
    "agent-5": "resolver",
    "agent-6": "coordinator",
}

@dataclass(frozen=True)
class ToolSpec:
    action_type: str
    description: str
    example: dict[str, str]
    operation: str | None = None

    @property
    def arguments(self) -> tuple[str, ...]:
        return tuple(self.example)


TOOL_SPECS = {
    "read_file": ToolSpec("file_read", "Request a scoped file read", {"path": "/work/input/task.json"}),
    "write_file": ToolSpec("file_write", "Request a scoped file write", {"path": "/work/tmp/report", "payload": "result ok"}),
    "run_python": ToolSpec("tool_exec", "Propose Python execution (simulation only)", {}, "python"),
    "send_result": ToolSpec("net_send", "Request delivery to an approved host", {"host": "api.internal.svc", "payload": "result ok"}),
    "resolve_host": ToolSpec("dns_resolve", "Request resolution of an approved host", {"host": "api.internal.svc"}),
    "publish_message": ToolSpec("bus_publish", "Request a shared-bus publication", {"payload": "result ok"}),
    "count_words": ToolSpec("tool_exec", "Count whitespace-separated words", {"text": "hello world"}, "count_words"),
    "count_lines": ToolSpec("tool_exec", "Count logical lines using splitlines", {"text": "one\ntwo\n"}, "count_lines"),
    "search_text": ToolSpec("tool_exec", "Find lines containing a literal substring", {"text": "one\ntwo", "query": "two"}, "search_text"),
    "replace_text": ToolSpec("tool_exec", "Replace all literal substring matches", {"text": "hello world", "old": "world", "new": "team"}, "replace_text"),
    "sort_lines": ToolSpec("tool_exec", "Sort lines lexicographically", {"text": "b\na"}, "sort_lines"),
    "unique_lines": ToolSpec("tool_exec", "Remove duplicate lines, preserving first occurrence", {"text": "a\nb\na"}, "unique_lines"),
    "parse_json": ToolSpec("tool_exec", "Parse a JSON string into a value", {"text": "{\"ok\":true}"}, "parse_json"),
    "format_json": ToolSpec("tool_exec", "Pretty-print JSON with sorted object keys", {"text": "{\"b\":2,\"a\":1}"}, "format_json"),
    "select_json": ToolSpec("tool_exec", "Select an exact top-level JSON object key", {"text": "{\"name\":\"sentinel\"}", "key": "name"}, "select_json"),
    "csv_to_json": ToolSpec("tool_exec", "Convert a CSV header and rows into JSON records", {"text": "name,score\nAda,3\n"}, "csv_to_json"),
    "json_to_csv": ToolSpec("tool_exec", "Convert flat JSON records with identical keys into CSV", {"text": "[{\"name\":\"Ada\",\"score\":3}]"}, "json_to_csv"),
    "hash_text": ToolSpec("tool_exec", "Compute the SHA-256 hex digest of UTF-8 text", {"text": "hello"}, "hash_text"),
    "encode_base64": ToolSpec("tool_exec", "Base64-encode UTF-8 text", {"text": "hello"}, "encode_base64"),
    "decode_base64": ToolSpec("tool_exec", "Strictly decode Base64 into UTF-8 text", {"text": "aGVsbG8="}, "decode_base64"),
}

TOOL_TYPES = {name: spec.action_type for name, spec in TOOL_SPECS.items()}
# Fixed operation names, never shell commands. Python remains abstract-only.
TOOL_BINARIES = frozenset(spec.operation for spec in TOOL_SPECS.values() if spec.operation)
TRANSFORM_TOOLS = frozenset(name for name, spec in TOOL_SPECS.items()
                            if spec.operation and name != "run_python")

ROLE_TOOLS = {
    "researcher": ("read_file", "search_text", "parse_json", "select_json"),
    "writer": ("write_file", "replace_text", "format_json"),
    "analyst": ("run_python", "count_words", "count_lines", "csv_to_json", "json_to_csv"),
    "reporter": ("send_result", "hash_text"),
    "resolver": ("resolve_host", "encode_base64", "decode_base64"),
    "coordinator": ("publish_message", "sort_lines", "unique_lines"),
}

MAX_ARGUMENT_BYTES = 16384


def validate_arguments(name: str, arguments: dict) -> None:
    if not isinstance(name, str) or name not in TOOL_SPECS:
        raise ValueError("unknown tool")
    if not isinstance(arguments, dict) or set(arguments) != set(TOOL_SPECS[name].arguments):
        raise ValueError(f"{name} requires exactly {TOOL_SPECS[name].arguments}")
    if any(not isinstance(value, str) for value in arguments.values()):
        raise ValueError("tool arguments must be strings")
    if sum(len(value.encode("utf-8")) for value in arguments.values()) > MAX_ARGUMENT_BYTES:
        raise ValueError("tool arguments exceed 16384 bytes")


def tool_prompt() -> str:
    return " ".join(f"{name}({','.join(spec.arguments)}): {spec.description}."
                    for name, spec in TOOL_SPECS.items())
