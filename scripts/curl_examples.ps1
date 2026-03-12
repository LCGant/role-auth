param(
    [string]$BaseUrl = "http://localhost:8080"
)
$cookie = New-TemporaryFile

# Register
Invoke-RestMethod -Method Post -Uri "$BaseUrl/register" -ContentType "application/json" -Headers @{"X-Client-Family"="cli"} -Body '{"email":"alice@example.com","username":"alice","password":"StrongP@ss1"}' -SkipHttpErrorCheck

Write-Host "Confirme o email com o token entregue pelo seu canal de verificacao antes do login."

# Login
$resp = Invoke-WebRequest -Method Post -Uri "$BaseUrl/login" -ContentType "application/json" -Headers @{"X-Client-Family"="cli"} -Body '{"identifier":"alice@example.com","password":"StrongP@ss1"}' -SessionVariable session -SkipHttpErrorCheck

# Me
Invoke-WebRequest -Method Get -Uri "$BaseUrl/me" -WebSession $session -SkipHttpErrorCheck | Select-Object -ExpandProperty Content

Remove-Item $cookie -ErrorAction SilentlyContinue
