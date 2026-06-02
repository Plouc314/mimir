# Coding Conventions

## Imports

All imports are declared at the top of the file, in the following order, separated by a blank line:

1. Standard library
2. Third-party (`cryptography`)
3. Local modules

No inline or deferred imports.

## Type Annotations

All function signatures (parameters and return types) and class attributes carry type annotations.

Target: **Python 3.9**. This means:
- Use built-in generic types: `list[str]`, `dict[str, int]`, `tuple[str, ...]`
- Use `Optional[X]` and `Union[X, Y]` from `typing` — the `X | Y` syntax is 3.10+
- Use `from __future__ import annotations` at the top of every module to enable forward references without runtime cost

```python
from __future__ import annotations

from typing import Optional

def find(self, name: str) -> Optional[Namespace]:
    ...
```

## Classes

Define a class for each distinct concept in the domain (e.g. `Vault`, `Namespace`, `Entry`, `Session`, `Config`). Avoid bare dicts or tuples to represent structured data — use a class or `dataclass` instead.

## Global Variables

No mutable global state. Module-level constants are allowed and should be named in `UPPER_SNAKE_CASE`:

```python
MAGIC = b"MIMIR"
FORMAT_VERSION = 0x01
DEFAULT_SESSION_TIMEOUT = 900
```

## Testing

No unit tests. The test suite consists of **integration tests** that exercise the CLI end-to-end: they invoke commands against a real (temporary) vault file and assert on the output and resulting file state. Each test sets up its own isolated environment (tmp dir, fresh vault) and tears it down after.
