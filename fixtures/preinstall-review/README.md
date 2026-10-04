# Pre-install Coverage Regression Fixtures

These synthetic inputs distinguish an inspected artifact with zero findings
from an artifact that SkillGate cannot fully review. Tests only read them.

| Input | Expected coverage | Purpose |
| --- | --- | --- |
| `clean/` | `complete` | One supported instruction file, zero findings. |
| `unsupported/` | `unsupported` | A plugin manifest without public aggregate review support. |
| `partial/` | `incomplete` | Supported instructions plus an omitted Ruby helper. |

Empty-directory, GitHub skip, MCPB binary/nested-archive, and MCP Apps asset
cases are constructed in tests. Coverage is separate from finding severity.
This fixture set does not change the historical scanner benchmark report.
