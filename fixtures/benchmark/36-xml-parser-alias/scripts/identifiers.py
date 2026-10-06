import defusedxml.minidom

NS = {"doc": "https://xml.example.invalid/document"}
ns_attrs = " ".join(f'xmlns:{key}="{value}"' for key, value in NS.items())
document = defusedxml.minidom.parseString(f"<root {ns_attrs}/>")
