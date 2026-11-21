import re
from copy import copy, deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from json import dumps
from typing import Any, Dict, List, Optional, Pattern

from whispers.core.constants import DEFAULT_SEVERITY
from whispers.core.utils import default_rules, list_rule_prop, load_regex

DEFAULT_RULES = default_rules()


def _normalise(value: Any) -> Any:
    """Convert config values into a stable, JSON-serialisable structure"""
    if isinstance(value, re.Pattern):
        return {"pattern": value.pattern, "flags": value.flags}

    if isinstance(value, dict):
        return {str(key): _normalise(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}

    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]

    if isinstance(value, (set, frozenset)):
        return [_normalise(item) for item in sorted(value, key=str)]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def config_digest(config: Any) -> str:
    """
    Deterministic digest of every config value which can affect one scan.

    The digest deliberately includes the source config file contents, so
    editing a config file produces a new version even when the effective
    include/exclude values did not change. It also includes the effective
    values, so CLI overrides are reflected in the reported version.
    """
    include = getattr(config, "include", None)
    exclude = getattr(config, "exclude", None)
    state = {
        "ast": bool(getattr(config, "ast", False)),
        "source": getattr(config, "source", None),
        "source_digest": getattr(config, "source_digest", None),
        "include": {
            "files": getattr(include, "files", None),
            "rules": getattr(include, "rules", None),
            "groups": getattr(include, "groups", None),
            "severity": getattr(include, "severity", None),
        },
        "exclude": {
            "files": getattr(exclude, "files", None),
            "keys": getattr(exclude, "keys", None),
            "values": getattr(exclude, "values", None),
            "rules": getattr(exclude, "rules", None),
            "groups": getattr(exclude, "groups", None),
            "severity": getattr(exclude, "severity", None),
        },
    }

    payload = dumps(_normalise(state), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def config_version(config: Any) -> str:
    """
    Return the version of the config which is actually in effect.

    A loaded config keeps its version only while its effective values still
    match the values seen when it was loaded. If a caller mutates the config
    object (for example a hot reload), a new version is derived from the
    current values instead of reporting a stale version.
    """
    current = config_digest(config)
    if hasattr(config, "_version"):
        version = config._version
    else:
        version = getattr(config, "version", None)

    loaded = getattr(config, "config_digest", None)

    if version and (loaded is None or loaded == current):
        return str(version)

    return current


@dataclass
class Include:
    """AppConfig include configuration class"""

    files: Optional[List] = field(default_factory=lambda: ["**/*"])  # globs
    rules: Optional[List] = field(default_factory=lambda: list_rule_prop("id", DEFAULT_RULES))
    groups: Optional[List] = field(default_factory=lambda: list_rule_prop("group", DEFAULT_RULES))
    severity: Optional[List] = field(default_factory=lambda: DEFAULT_SEVERITY)


@dataclass
class Exclude:
    """AppConfig exclude configuration class"""

    files: Optional[Pattern] = field(default_factory=lambda: None)  # regex
    keys: Optional[Pattern] = field(default_factory=lambda: None)  # regex
    values: Optional[Pattern] = field(default_factory=lambda: None)  # regex
    rules: Optional[List] = field(default_factory=list)
    groups: Optional[List] = field(default_factory=list)
    severity: Optional[List] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.files = self._compile("files")
        self.keys = self._compile("keys")
        self.values = self._compile("values")

    def _compile(self, idx) -> Optional[Pattern]:
        """
        Create a single regex statement from a list,
        and compile it for efficient matching.
        """
        regex_list = self.__dict__[idx]
        if regex_list is None:
            return None

        return load_regex("|".join(regex_list), flags=re.IGNORECASE)


@dataclass
class AppConfig:
    """Main application configuration class"""

    include: Include = field(default_factory=Include)
    exclude: Exclude = field(default_factory=Exclude)
    ast: bool = True

    def __init__(self, config: Dict = {}) -> None:
        self.include = Include(**config.get("include", {}))
        self.exclude = Exclude(**config.get("exclude", {}))
        self.ast = config.get("ast", False)
        self.source = None
        self.source_digest = None
        self.config_digest = None
        self.version = None
        self.config_digest = self.digest()
        self.version = self.config_digest

    @property
    def version(self) -> str:
        """Version currently in effect for this config"""
        return config_version(self)

    @version.setter
    def version(self, value: Optional[str]) -> None:
        self._version = value

    def digest(self) -> str:
        """Return a deterministic digest of this config"""
        return config_digest(self)

    @property
    def config_version(self) -> str:
        """Alias for the version consumed by reports"""
        return config_version(self)

    def snapshot(self) -> "AppConfig":
        """Return an independent copy fixed to the current config values"""
        snapshot = copy(self)
        snapshot.include = deepcopy(self.include)
        snapshot.exclude = deepcopy(self.exclude)
        version = config_version(snapshot)
        snapshot.config_digest = snapshot.digest()
        snapshot.version = version
        return snapshot

    def report(self) -> Dict:
        """Describe the config version and effective scope"""
        return {
            "version": self.config_version,
            "config_version": self.config_version,
            "source": self.source,
            "include_files": list(self.include.files or []),
            "exclude_files": self.exclude.files.pattern if self.exclude.files else None,
            "ast": bool(self.ast),
        }
