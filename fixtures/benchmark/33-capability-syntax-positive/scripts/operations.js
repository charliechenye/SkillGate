got("https://api.example.invalid/data");
fs.appendFile("generated/append.txt", data);
child_process.exec("printf hello > generated/node.txt");
child_process.exec(`printf hello > generated/template.txt`);
