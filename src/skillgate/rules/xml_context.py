"""Recognize XML identifiers only when their static consumers are explicit."""

from __future__ import annotations

import ast
import re
from collections import defaultdict

XMLNS_RE = re.compile(r"\bxmlns(?::[\w.-]+)?\s*=\s*['\"]https?://[^'\"\s<>]+['\"]")
URI_RE = re.compile(r"https?://[^\s]+\Z")
XML_PARSERS = {
    "xml.dom.minidom.parseString",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XML",
    "xml.etree.ElementTree.register_namespace",
    "lxml.etree.fromstring",
    "lxml.etree.XML",
    "lxml.etree.register_namespace",
    "defusedxml.minidom.parseString",
    "defusedxml.ElementTree.fromstring",
    "defusedxml.ElementTree.XML",
}


def _dotted_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    return ".".join([node.id, *reversed(parts)])


def _import_bindings(tree: ast.AST) -> dict[str, str]:
    bindings: dict[str, set[str | None]] = defaultdict(set)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                bindings[local].add(alias.name if alias.asname else local)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                bindings[alias.asname or alias.name].add(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Name | ast.Attribute) and isinstance(
            node.ctx, ast.Store | ast.Del
        ):
            local = _dotted_name(node).split(".")[0]
            bindings[local].add(None)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bindings[node.name].add(None)
        elif isinstance(node, ast.arg):
            bindings[node.arg].add(None)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bindings[node.name].add(None)
    return {
        name: next(iter(paths))
        for name, paths in bindings.items()
        if len(paths) == 1 and None not in paths
    }


def without_xml_identifiers(text: str) -> str:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return text
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    imports = _import_bindings(tree)

    def is_xml_parser(node: ast.AST) -> bool:
        name, dot, suffix = _dotted_name(node).partition(".")
        imported = imports.get(name)
        return imported is not None and imported + dot + suffix in XML_PARSERS

    loads: dict[str, list[ast.Name]] = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loads[node.id].append(node)

    def only_xml_use(
        node: ast.AST,
        visiting: frozenset[ast.AST] = frozenset(),
        slots: frozenset[int] | None = None,
        mapping: bool = False,
        rows: bool = False,
    ) -> bool:
        if node in visiting or node not in parents or len(visiting) >= 32:
            return False
        visiting = visiting | {node}
        parent = parents[node]
        if isinstance(parent, ast.Assign | ast.AnnAssign) and parent.value is node:
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            return all(
                isinstance(target, ast.Name)
                and bool(loads[target.id])
                and all(
                    only_xml_use(use, visiting, slots, mapping, rows) for use in loads[target.id]
                )
                for target in targets
            )
        if isinstance(parent, ast.For | ast.comprehension) and parent.iter is node:
            if isinstance(parent.target, ast.Name):
                return all(only_xml_use(use, visiting, slots) for use in loads[parent.target.id])
            targets = (
                parent.target.elts
                if isinstance(parent.target, ast.Tuple | ast.List)
                else [parent.target]
            )
            selected = [
                target for index, target in enumerate(targets) if slots is None or index in slots
            ]
            if slots is not None and any(index >= len(targets) for index in slots):
                return False
            return all(
                isinstance(target, ast.Name)
                and all(only_xml_use(use, visiting) for use in loads[target.id])
                for target in selected
            )
        if isinstance(parent, ast.Attribute) and parent.attr in {"items", "values"}:
            call = parents.get(parent)
            if (
                isinstance(call, ast.Call)
                and call.func is parent
                and not call.args
                and not call.keywords
            ):
                item_slots = frozenset({1}) if mapping and parent.attr == "items" else None
                return only_xml_use(call, visiting, item_slots, rows=item_slots is not None)
            return False
        if isinstance(parent, ast.Subscript) and parent.value is node:
            if rows:
                return only_xml_use(parent, visiting, slots)
            if slots is not None and isinstance(parent.slice, ast.Constant):
                if parent.slice.value not in slots:
                    return True
            return only_xml_use(parent, visiting)
        if isinstance(parent, ast.keyword):
            call = parents.get(parent)
            return (
                parent.arg in {"namespaces", "nsmap"}
                and isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in {"find", "findall", "findtext", "xpath", "iterfind"}
            )
        if isinstance(parent, ast.Call):
            name = (
                parent.func.attr
                if isinstance(parent.func, ast.Attribute)
                else getattr(parent.func, "id", "")
            )
            if is_xml_parser(parent.func) and node in parent.args:
                return True
            if name == "setAttribute" and len(parent.args) == 2 and node is parent.args[1]:
                attribute = parent.args[0]
                return (
                    isinstance(attribute, ast.Constant)
                    and isinstance(attribute.value, str)
                    and (attribute.value == "Type" or attribute.value.startswith("xmlns"))
                )
            if (
                name == "join"
                and isinstance(parent.func, ast.Attribute)
                and isinstance(parent.func.value, ast.Constant)
                and node in parent.args
            ):
                return only_xml_use(parent, visiting)
            return False
        if isinstance(parent, ast.Compare) and node in parent.comparators:
            left = parent.left
            return (
                len(parent.ops) == 1
                and isinstance(parent.ops[0], ast.In | ast.NotIn)
                and isinstance(left, ast.Call)
                and isinstance(left.func, ast.Attribute)
                and left.func.attr == "getAttribute"
                and len(left.args) == 1
                and isinstance(left.args[0], ast.Constant)
                and left.args[0].value == "Type"
            )
        if isinstance(
            parent,
            ast.JoinedStr
            | ast.FormattedValue
            | ast.GeneratorExp
            | ast.ListComp
            | ast.SetComp
            | ast.DictComp
            | ast.List
            | ast.Tuple
            | ast.Set
            | ast.Dict
            | ast.BinOp,
        ):
            return only_xml_use(parent, visiting, slots, mapping, rows)
        return False

    lines = text.encode("utf-8").splitlines(keepends=True)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if URI_RE.fullmatch(node.value):
            parent = parents.get(node)
            slots = None
            mapping = False
            container: ast.AST = node
            if isinstance(parent, ast.Dict) and node in parent.values:
                # URI keys are not namespace prefixes; keep ambiguous mappings.
                if any(
                    not isinstance(key, ast.Constant)
                    or not isinstance(key.value, str)
                    or URI_RE.fullmatch(key.value)
                    for key in parent.keys
                ):
                    continue
                container, mapping = parent, True
            elif isinstance(parent, ast.Tuple | ast.List):
                outer = parents.get(parent)
                if isinstance(outer, ast.List | ast.Tuple):
                    if not all(isinstance(item, ast.Tuple | ast.List) for item in outer.elts):
                        continue
                    slots = frozenset(
                        index
                        for item in outer.elts
                        for index, value in enumerate(item.elts)
                        if isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                        and URI_RE.fullmatch(value.value)
                    )
                    container = outer
            if not only_xml_use(container, slots=slots, mapping=mapping, rows=slots is not None):
                continue
            _mask_node(lines, node)
        elif XMLNS_RE.search(node.value):
            # Mask only xmlns attributes, retaining any other URLs in the XML.
            for index in range(node.lineno - 1, node.end_lineno):
                line = lines[index].decode("utf-8")
                lines[index] = XMLNS_RE.sub(
                    lambda match: " " * len(match[0].encode("utf-8")), line
                ).encode("utf-8")
    return b"".join(lines).decode("utf-8")


def _mask_node(lines: list[bytes], node: ast.Constant) -> None:
    # AST columns count UTF-8 bytes; keep offsets and physical lines intact.
    for index in range(node.lineno - 1, node.end_lineno):
        start = node.col_offset if index == node.lineno - 1 else 0
        end = (
            node.end_col_offset
            if index == node.end_lineno - 1
            else len(lines[index].rstrip(b"\r\n"))
        )
        lines[index] = lines[index][:start] + b" " * (end - start) + lines[index][end:]
