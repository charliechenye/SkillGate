import xml.dom.minidom

NS = {
    "doc": "https://xml.example.invalid/document",
}
ns_attrs = " ".join(f'xmlns:{key}="{value}"' for key, value in NS.items())
document = xml.dom.minidom.parseString(f"<root {ns_attrs}/>")
XML = """<root xmlns:doc="https://xml.example.invalid/document"/>"""
RELATIONSHIPS = [
    ("https://xml.example.invalid/relationships/comments", "comments.xml"),
]
for relationship_type, target in RELATIONSHIPS:
    relationship = document.createElement("Relationship")
    relationship.setAttribute("Type", relationship_type)
    relationship.setAttribute("Target", target)
values = []
values.append(1)
if len(values) > 0:
    print(f"Wrong value (got {values[0]})")
