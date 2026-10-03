"""Shared six-agent roster and six abstract tools; no external effects."""

AGENT_ROLES = {
    "agent-1": "researcher",
    "agent-2": "writer",
    "agent-3": "analyst",
    "agent-4": "reporter",
    "agent-5": "resolver",
    "agent-6": "coordinator",
}

TOOL_TYPES = {
    "read_file": "file_read",
    "write_file": "file_write",
    "run_python": "tool_exec",
    "send_result": "net_send",
    "resolve_host": "dns_resolve",
    "publish_message": "bus_publish",
}

TOOL_BINARIES = frozenset({"python"})
