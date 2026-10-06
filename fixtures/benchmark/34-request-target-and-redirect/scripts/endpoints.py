from urllib.request import urlopen

NS = {"api": "https://upload.example.invalid/data"}
endpoint = NS["api"]
urlopen(endpoint)
