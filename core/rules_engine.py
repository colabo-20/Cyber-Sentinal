"""CyberSentinel Rules Engine.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import RULES_DIR


@dataclass
class Rule:
    """Custom detection rule.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    rule_id: str
    name: str
    description: str
    rule_type: str
    pattern: str
    severity: str
    enabled: bool = True
    hits: int = 0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Rule":
        return cls(**data)


class RulesEngine:
    """Engine for custom rules.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.rules_path = RULES_DIR / "custom_rules.json"
        self.rules: List[Rule] = []
        self._load_rules()

    def _default_rules(self) -> List[Rule]:
        return [
            Rule("R001", "Executable Detection", "Detect executable extensions", "extension", r"\.(exe|dll|sys)$", "high"),
            Rule("R002", "Script Detection", "Detect script extensions", "extension", r"\.(ps1|vbs|js|bat)$", "medium"),
            Rule("R003", "Archive Bomb", "Detect large archives", "extension", r"\.(zip|rar|7z)$", "low"),
            Rule("R004", "Ransomware Note", "Detect ransom note names", "filename", r"(readme|decrypt|restore|recover|ransom)", "critical"),
            Rule("R005", "Credential File", "Detect credential files", "filename", r"(password|secret|cred)", "high"),
            Rule("R006", "Hidden File Monitor", "Hidden file detection", "filename", r"^\.", "medium"),
            Rule("R007", "Large File Alert", "Large file", "size", r"104857600", "low"),
            Rule("R008", "Temp File Detection", "Temp file", "filename", r"\.tmp$", "low"),
            Rule("R009", "Web Shell Detection", "Detect web shells", "content", r"(eval\(|base64_decode\()", "critical"),
            Rule("R010", "Crypto Miner Detection", "Detect crypto miners", "content", r"(xmrig|minerd|cryptonight)", "critical"),
        ]

    def _load_rules(self) -> None:
        try:
            if self.rules_path.exists():
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.rules = [Rule.from_dict(r) for r in data]
            if not self.rules:
                self.rules = self._default_rules()
                self._save_rules()
        except Exception:
            self.rules = self._default_rules()
            self._save_rules()

    def _save_rules(self) -> None:
        try:
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.rules_path, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in self.rules], f, indent=2)
        except Exception:
            pass

    def evaluate_file(self, filepath: str) -> List[Dict[str, object]]:
        """Evaluate file against rules.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        hits: List[Dict[str, object]] = []
        filename = os.path.basename(filepath)
        extension = os.path.splitext(filename)[1].lower()
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                if rule.rule_type == "filename" and re.search(rule.pattern, filename, re.IGNORECASE):
                    rule.hits += 1
                    hits.append(rule.to_dict())
                elif rule.rule_type == "extension" and re.search(rule.pattern, extension, re.IGNORECASE):
                    rule.hits += 1
                    hits.append(rule.to_dict())
                elif rule.rule_type == "path" and re.search(rule.pattern, filepath, re.IGNORECASE):
                    rule.hits += 1
                    hits.append(rule.to_dict())
                elif rule.rule_type == "content":
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(50 * 1024)
                        if re.search(rule.pattern, content, re.IGNORECASE):
                            rule.hits += 1
                            hits.append(rule.to_dict())
                    except Exception:
                        continue
                elif rule.rule_type == "size":
                    try:
                        size = os.path.getsize(filepath)
                        if size > int(rule.pattern):
                            rule.hits += 1
                            hits.append(rule.to_dict())
                    except Exception:
                        continue
            except Exception:
                continue
        self._save_rules()
        return hits

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)
        self._save_rules()

    def remove_rule(self, rule_id: str) -> None:
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        self._save_rules()

    def toggle_rule(self, rule_id: str) -> None:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = not rule.enabled
        self._save_rules()

    def get_all_rules(self) -> List[Rule]:
        return self.rules

    def get_enabled_rules(self) -> List[Rule]:
        return [r for r in self.rules if r.enabled]
