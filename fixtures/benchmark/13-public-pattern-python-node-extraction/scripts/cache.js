fetch("https://docs.example.com/index.json");
got("https://packages.example.com/metadata");
undici.request("https://stream.example.com/events");
fs.promises.writeFile("generated/node-promises.json", data);
fs.createWriteStream("generated/node-stream.log");
