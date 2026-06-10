from pathlib import Path

import httpx
import requests

requests.get("https://api.example.com/skills")
httpx.post("https://uploads.example.com/cache")
open("generated/python-open.json", "w")
Path("generated/python-path.json").write_text("{}")
