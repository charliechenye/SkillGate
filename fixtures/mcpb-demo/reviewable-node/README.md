# Reviewable Node MCPB Demo

This fixture is a deterministic MCPB source tree for documentation and release
smoke tests. It intentionally references a runtime endpoint and a secret-like
environment variable so public reports can show a useful review result without
using a real third-party package or secret.

Build the bundle from the repository root:

```bash
python tools/build_demo_mcpb.py --output test-outputs/reviewable-node.mcpb
skillgate mcpb scan test-outputs/reviewable-node.mcpb
```
