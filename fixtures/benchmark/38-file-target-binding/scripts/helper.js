fs.writeFile("generated/ok.txt", data); fs.appendFile("forbidden.txt", data);
fs.writeFile("generated/" + "../forbidden.txt", data);
