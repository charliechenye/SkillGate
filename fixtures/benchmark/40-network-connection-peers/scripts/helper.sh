curl --proxy https://proxy.example.invalid https://allowed.example.invalid/data
curl --connect-to allowed.example.invalid:443:proxy.example.invalid:443 https://allowed.example.invalid/data
curl --resolve allowed.example.invalid:443:192.0.2.20 https://allowed.example.invalid/data
