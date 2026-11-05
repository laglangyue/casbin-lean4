#!/usr/bin/env python3
"""Extract literal builtin expectations without changing the Go tests."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
source = (root / "util/builtin_operators_test.go").read_text()
argument = r'"(?:[^"\\]|\\.)*"|`[^`]*`|true|false|-?[0-9]+'
cases = []
for match in re.finditer(r'(?m)^\s*test(Key\w*|RegexMatch(?:Func)?|GlobMatch(?:Func)?|IPMatch(?:Func)?)\(t, (.+)\)\s*(?://.*)?$', source):
    raw = match[2]
    args = re.findall(argument, raw)
    if re.sub(argument, "", raw).strip(" ,"):
        raise ValueError(f"Nonliteral upstream case: {raw}")
    values = [json.loads(arg) if not arg.startswith("`") else arg[1:-1] for arg in args]
    name = match[1]
    is_wrapper = name.endswith("Func")
    if is_wrapper:
        name = name[:-4]
    name = "ipMatch" if name == "IPMatch" else name[0].lower() + name[1:]
    row = {"name": name, "args": values[2:] if is_wrapper else values[:-1]}
    if not is_wrapper:
        row["legacy"] = True
    if is_wrapper and values[1]:
        row["error"] = values[1]
    else:
        row["expected"] = values[0] if is_wrapper else values[-1]
    cases.append(row)
target = root / "Test/data/builtin.json"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n")
print(f"Extracted {len(cases)} upstream builtin cases")
