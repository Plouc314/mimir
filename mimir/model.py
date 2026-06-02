from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Entry:
    key: str
    value: str
    sensitive: bool


@dataclass
class Namespace:
    name: str
    entries: list[Entry] = field(default_factory=list)

    def get(self, key: str) -> Optional[Entry]:
        for entry in self.entries:
            if entry.key == key:
                return entry
        return None

    def set(self, key: str, value: str, sensitive: bool) -> None:
        for i, entry in enumerate(self.entries):
            if entry.key == key:
                self.entries[i] = Entry(key, value, sensitive)
                return
        self.entries.append(Entry(key, value, sensitive))

    def delete(self, key: str) -> bool:
        for i, entry in enumerate(self.entries):
            if entry.key == key:
                del self.entries[i]
                return True
        return False


@dataclass
class Vault:
    salt: bytes = b""
    version: int = 0
    modified: int = 0
    namespaces: list[Namespace] = field(default_factory=list)

    def find(self, name: str) -> Optional[Namespace]:
        for ns in self.namespaces:
            if ns.name == name:
                return ns
        return None

    def add(self, name: str) -> Namespace:
        ns = Namespace(name=name)
        self.namespaces.append(ns)
        return ns

    def delete(self, name: str) -> bool:
        for i, ns in enumerate(self.namespaces):
            if ns.name == name:
                del self.namespaces[i]
                return True
        return False

    def to_json(self) -> bytes:
        data = {
            "namespaces": [
                {
                    "name": ns.name,
                    "entries": [
                        {"key": e.key, "value": e.value, "sensitive": e.sensitive}
                        for e in ns.entries
                    ],
                }
                for ns in self.namespaces
            ]
        }
        return json.dumps(data).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> Vault:
        obj = json.loads(data.decode("utf-8"))
        namespaces = []
        for ns_data in obj["namespaces"]:
            entries = [
                Entry(e["key"], e["value"], e["sensitive"])
                for e in ns_data["entries"]
            ]
            namespaces.append(Namespace(name=ns_data["name"], entries=entries))
        return cls(namespaces=namespaces)
