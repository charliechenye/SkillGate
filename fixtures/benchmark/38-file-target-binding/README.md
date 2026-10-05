# File target binding

Authored regression for multiple writes on one line, computed paths, and escaped
Python strings. Report every target. Decode Python literals; retain unknown
targets for expressions and parent traversal instead of allowlisting a prefix.

Scan statically; never execute these fixtures.
