"""
Detection rules for MCPCheck.

Each rule is an independent, testable unit that checks for specific
security issues in MCP manifests.
"""

from mcpcheck.rules.base import BaseRule, Rule
from mcpcheck.rules.tool_poison import (
    ToolPoisonSystemOverride,
    ToolPoisonImperativeInjection,
    ToolPoisonHiddenUnicode,
)
from mcpcheck.rules.over_permission import (
    OverPermissionDangerousCombo,
    OverPermissionUnrestrictedWrite,
)
from mcpcheck.rules.dynamic_schema import (
    DynamicSchemaRemoteLoading,
    DynamicSchemaUnpinnedHash,
)
from mcpcheck.rules.auth_exposure import (
    AuthExposurePlaintextToken,
    AuthExposureNotGitignored,
)

# Default ruleset for Phase 1 (v0.1.0)
DEFAULT_RULES: list[Rule] = [
    # Tool poisoning rules
    ToolPoisonSystemOverride(),
    ToolPoisonImperativeInjection(),
    ToolPoisonHiddenUnicode(),
    # Over-permission rules
    OverPermissionDangerousCombo(),
    OverPermissionUnrestrictedWrite(),
    # Dynamic schema rules
    DynamicSchemaRemoteLoading(),
    DynamicSchemaUnpinnedHash(),
    # Auth exposure rules
    AuthExposurePlaintextToken(),
    AuthExposureNotGitignored(),
]

__all__ = [
    # Base
    "BaseRule",
    "Rule",
    # Tool poison
    "ToolPoisonSystemOverride",
    "ToolPoisonImperativeInjection",
    "ToolPoisonHiddenUnicode",
    # Over-permission
    "OverPermissionDangerousCombo",
    "OverPermissionUnrestrictedWrite",
    # Dynamic schema
    "DynamicSchemaRemoteLoading",
    "DynamicSchemaUnpinnedHash",
    # Auth exposure
    "AuthExposurePlaintextToken",
    "AuthExposureNotGitignored",
    # Ruleset
    "DEFAULT_RULES",
]
