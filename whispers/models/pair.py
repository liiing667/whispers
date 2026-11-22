from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(init=False)
class KeyValuePair:
    """Main key-value pair class"""

    key: str
    value: str
    keypath: List = field(default_factory=list)
    file: str = ""
    line: int = 0
    rule: object = None

    def __init__(
        self,
        key: str,
        value: str,
        keypath: List = None,
        file: str = "",
        line: int = 0,
        rule: object = None,
        **history,
    ) -> None:
        self.key = key
        self.value = value
        self.keypath = [] if keypath is None else keypath
        self.file = file
        self.line = line
        self.rule = rule
        self.__post_init__()

        commit = history.get("commit", history.get("commit_sha"))
        blob = history.get("blob", history.get("blob_sha", history.get("object_id")))
        path = history.get("path")
        generation = history.get("generation", history.get("scan_generation"))
        stage = history.get("stage", history.get("detection_stage", history.get("phase")))
        if commit is not None:
            self.commit = commit
            self.commit_sha = commit
        if blob is not None:
            self.blob = blob
            self.blob_sha = blob
            self.object_id = blob
        if path is not None:
            self.path = path
        if generation is not None:
            self.generation = generation
            self.scan_generation = generation
        if history.get("generation_id") is not None:
            self.generation_id = history["generation_id"]
        if stage is not None:
            self.stage = stage
            self.detection_stage = stage
            self.phase = stage
        for name in ("id", "finding_id", "history"):
            value = history.get(name)
            if value is not None:
                setattr(self, name, value)

    def __post_init__(self) -> None:
        if self.keypath == []:
            self.keypath = [self.key]

    def __repr__(self) -> str:
        return f"[{self.file}:{self.line}] {self.key} = {self.value}"

    def to_json(self) -> Dict:
        result = {
            "key": self.key,
            "value": self.value,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule.id,
            "message": self.rule.message,
            "severity": self.rule.severity,
        }

        # History findings keep their commit/blob identity and audit stage.
        # Plain working-tree findings retain the original JSON shape.
        for name in (
            "id",
            "finding_id",
            "commit",
            "commit_sha",
            "blob",
            "blob_sha",
            "object_id",
            "path",
            "generation",
            "generation_id",
            "scan_generation",
            "stage",
            "detection_stage",
            "phase",
        ):
            value = self.__dict__.get(name)
            if value not in (None, ""):
                result[name] = value

        history = self.__dict__.get("history")
        if history and "history" not in result:
            result["history"] = history
        return result

    @property
    def is_history_finding(self) -> bool:
        """Whether this pair came from a frozen Git history snapshot"""
        return bool(
            self.__dict__.get("history")
            or self.__dict__.get("commit")
            or self.__dict__.get("blob")
        )

    @property
    def history_identity(self) -> Dict:
        """Stable identity fields for a history finding"""
        return {
            "generation": self.__dict__.get("generation"),
            "commit": self.__dict__.get("commit"),
            "blob": self.__dict__.get("blob"),
            "path": self.__dict__.get("path"),
            "key": self.key,
            "value": self.value,
            "line": self.line,
        }
