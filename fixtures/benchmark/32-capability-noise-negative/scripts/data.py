from xml.etree.ElementTree import Element

NS = {"doc": "https://xml.example.invalid/document"}
root = Element("root")
root.findall("doc:item", namespaces=NS)
