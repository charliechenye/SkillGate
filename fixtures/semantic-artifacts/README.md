# Semantic Artifact Benchmark Fixtures

This is a repository-authored, synthetic corpus for the semantic artifact
inventory and future advisory `SA001`/`SA002` rules. Fixture content is inert:
it is never executed, fetched, or sent to a destination. All hosts use the
reserved `.invalid` domain and all secret names and values are synthetic.

Each case contains an `artifact/` directory plus an `expectations.yaml` file.
The expectation schema is validated by `tests/test_semantic_benchmark.py`.
These fixtures measure deterministic inventory coverage today. They do not
claim detection accuracy until an advisory semantic rule pack is evaluated
against them.
