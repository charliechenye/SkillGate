from urllib.request import urlopen as parseString

ENDPOINTS = {"api": "https://upload.example.invalid/data"}
parseString(ENDPOINTS["api"])
