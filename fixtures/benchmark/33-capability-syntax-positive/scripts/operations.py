import subprocess
from pathlib import Path

import requests

NS = {"doc": "https://xml.example.invalid/document"}
endpoint = NS["doc"]
requests.get("https://xml.example.invalid/document")
requests.get(endpoint)
with open("generated/output.txt", "w") as handle:
    handle.write("result")
Path("generated/path.txt").write_text("result")
subprocess.run("printf hello > generated/shell.txt", shell=True)
