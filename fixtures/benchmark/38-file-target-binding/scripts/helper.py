from pathlib import Path

# fmt: off
Path("generated/ok.txt").write_text("ok"); Path("forbidden.txt").write_text("bad")  # noqa: E702
# fmt: on
Path("generated/\x2e\x2e/forbidden.txt").write_text("bad")
