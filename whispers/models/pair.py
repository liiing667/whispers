from dataclasses import dataclass, field
from hashlib import sha256
from typing import Dict, List


@dataclass
class KeyValuePair:
    """Main key-value pair class"""

    key: str
    value: str
    keypath: List = field(default_factory=list)
    file: str = ""
    line: int = 0
    rule: object = None

    def __post_init__(self) -> None:
        if self.keypath == []:
            self.keypath = [self.key]

    @property
    def fingerprint(self) -> str:
        """Stable content-based fingerprint for correlating findings"""
        digest = sha256()
        for part in (self.file, self.key, self.value):
            digest.update(str(part).encode("utf-8", errors="replace"))
            digest.update(b"\0")

        return digest.hexdigest()

    @property
    def redacted_value(self) -> str:
        """Redacted value that preserves length and correlatability"""
        value = str(self.value)
        digest = sha256(value.encode("utf-8", errors="replace")).hexdigest()
        return f"<redacted:len={len(value)},sha256:{digest[:12]}>"

    def __repr__(self) -> str:
        return f"[{self.file}:{self.line}] {self.key} = {self.redacted_value} (fingerprint:{self.fingerprint[:12]})"

    def to_json(self, redact: bool = True) -> Dict:
        if not redact:
            # Legacy compatibility mode: raw plaintext values
            return {
                "key": self.key,
                "value": self.value,
                "file": self.file,
                "line": self.line,
                "rule_id": self.rule.id,
                "message": self.rule.message,
                "severity": self.rule.severity,
            }

        return {
            "key": self.key,
            "value": self.redacted_value,
            "value_length": len(str(self.value)),
            "fingerprint": self.fingerprint,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule.id,
            "message": self.rule.message,
            "severity": self.rule.severity,
        }
