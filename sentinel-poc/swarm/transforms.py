"""Bounded in-memory utilities. No filesystem, network, subprocess, or eval."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json

from sentinel.actions import Action, ActionType
from .catalog import TRANSFORM_TOOLS, validate_arguments

MAX_RESULT_BYTES = 65536


def _json(text):
    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")
    value = json.loads(text, parse_constant=invalid_constant)
    # Reject non-finite floats, including exponent overflow, and excessive depth.
    json.dumps(value, allow_nan=False)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            raise ValueError("JSON nesting exceeds 32 levels")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return value


def perform_transform(action: Action) -> dict:
    name = action.params.get("tool")
    if action.type != ActionType.TOOL_EXEC or name not in TRANSFORM_TOOLS:
        raise ValueError("only fixed in-memory transforms can execute here")
    args = {key: value for key, value in action.params.items() if key != "tool"}
    validate_arguments(name, args)
    text = args["text"]
    if name == "count_words":
        result = {"count": len(text.split())}
    elif name == "count_lines":
        result = {"count": len(text.splitlines())}
    elif name == "search_text":
        if not args["query"]:
            raise ValueError("query must not be empty")
        result = {"matches": [{"line": i, "text": line}
                              for i, line in enumerate(text.splitlines(), 1)
                              if args["query"] in line]}
    elif name == "replace_text":
        old, new = args["old"], args["new"]
        if not old:
            raise ValueError("old must not be empty")
        size = len(text.encode()) + text.count(old) * (len(new.encode()) - len(old.encode()))
        if size > MAX_RESULT_BYTES:
            raise ValueError("replacement exceeds result limit")
        result = {"content": text.replace(old, new)}
    elif name == "sort_lines":
        result = {"content": "\n".join(sorted(text.splitlines()))}
    elif name == "unique_lines":
        result = {"content": "\n".join(dict.fromkeys(text.splitlines()))}
    elif name == "parse_json":
        result = {"value": _json(text)}
    elif name == "format_json":
        result = {"content": json.dumps(_json(text), indent=2, sort_keys=True, ensure_ascii=False)}
    elif name == "select_json":
        value = _json(text)
        if not isinstance(value, dict) or args["key"] not in value:
            raise ValueError("key must exist in a JSON object")
        result = {"value": value[args["key"]]}
    elif name == "csv_to_json":
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        if not rows or not rows[0] or any(not key for key in rows[0]) or len(set(rows[0])) != len(rows[0]):
            raise ValueError("CSV requires unique nonempty headers")
        if any(len(row) != len(rows[0]) for row in rows[1:]):
            raise ValueError("CSV row width must match headers")
        result = {"value": [dict(zip(rows[0], row)) for row in rows[1:]]}
    elif name == "json_to_csv":
        rows = _json(text)
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict) or not rows[0]:
            raise ValueError("expected a nonempty array of nonempty flat objects")
        keys = list(rows[0])
        if any(not key for key in keys) or any(
            not isinstance(row, dict) or set(row) != set(keys)
            or any(isinstance(value, (dict, list)) for value in row.values()) for row in rows
        ):
            raise ValueError("CSV records must have identical nonempty keys and scalar values")
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=keys, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        result = {"content": output.getvalue()}
    elif name == "hash_text":
        result = {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    elif name == "encode_base64":
        result = {"content": base64.b64encode(text.encode("utf-8")).decode("ascii")}
    elif name == "decode_base64":
        result = {"content": base64.b64decode(text, validate=True).decode("utf-8")}
    else:
        raise ValueError("unknown transform")
    if len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode()) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds 65536 bytes")
    return result
