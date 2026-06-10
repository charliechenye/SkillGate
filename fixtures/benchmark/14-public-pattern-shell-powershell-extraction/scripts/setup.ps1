Invoke-RestMethod -Uri https://ps.example.com/bootstrap
Set-Content -Path generated/powershell.json -Value "{}"
Remove-Item generated/cache -Recurse
