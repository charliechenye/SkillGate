import requests

NS = {"doc": "https://xml.example.invalid/document"}
endpoint = NS["doc"]
requests.get("https://xml.example.invalid/document")
requests.get(endpoint)
