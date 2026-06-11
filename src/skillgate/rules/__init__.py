from skillgate.rules.config_rules import ConfigRule
from skillgate.rules.markdown_rules import PromptOverrideRule, SuspiciousUnicodeRule
from skillgate.rules.mcp_registry_rules import McpRegistryMetadataRule
from skillgate.rules.mcp_rules import McpConfigRule
from skillgate.rules.script_rules import (
    DestructiveCommandRule,
    FilesystemWriteRule,
    NetworkEgressRule,
    RemoteDownloadExecutionRule,
    SecretAccessRule,
    ShellExecutionRule,
)

DEFAULT_RULES = [
    RemoteDownloadExecutionRule(),
    ShellExecutionRule(),
    DestructiveCommandRule(),
    NetworkEgressRule(),
    SecretAccessRule(),
    FilesystemWriteRule(),
    PromptOverrideRule(),
    SuspiciousUnicodeRule(),
    McpConfigRule(),
    McpRegistryMetadataRule(),
    ConfigRule(),
]
