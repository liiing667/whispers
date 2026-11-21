from dataclasses import dataclass, field
from functools import cached_property
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

    @cached_property
    def fingerprint(self) -> str:
        """Stable, non-reversible identity shared by every finding of this value"""
        from whispers.core.utils import secret_fingerprint

        return secret_fingerprint(self.value)

    @cached_property
    def masked_value(self) -> str:
        """Deterministic redacted representation safe to write to logs"""
        from whispers.core.utils import mask_secret

        return mask_secret(self.value)

    def __repr__(self) -> str:
        # Never emit the raw value: logs may be retried, shipped or persisted.
        return f"[{self.file}:{self.line}] {self.key} = {self.masked_value} (fingerprint: {self.fingerprint})"

    def to_json(self) -> Dict:
        return {
            "key": self.key,
            "value": self.value,
            "masked_value": self.masked_value,
            "fingerprint": self.fingerprint,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule.id,
            "message": self.rule.message,
            "severity": self.rule.severity,
        }
