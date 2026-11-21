from dataclasses import dataclass, field
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

    def __repr__(self) -> str:
        return f"[{self.file}:{self.line}] {self.key} = {self.value}"

    def to_json(self) -> Dict:
        from whispers.core.finding import finding_id

        rule = self.rule
        return {
            "id": finding_id(self),
            "key": self.key,
            "value": self.value,
            "file": self.file,
            "line": self.line,
            "keypath": list(self.keypath),
            "rule_id": getattr(rule, "id", None),
            "rule_group": getattr(rule, "group", None),
            "message": getattr(rule, "message", None),
            "severity": getattr(rule, "severity", None),
        }
