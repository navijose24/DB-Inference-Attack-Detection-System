# Run this script in an Administrator PowerShell to reset MySQL root password to 'password'

Write-Host "[*] Stopping MySQL80 service..." -ForegroundColor Yellow
net stop MySQL80

$initFile = "C:\mysql_pass_reset.txt"
Set-Content -Path $initFile -Value "ALTER USER 'root'@'localhost' IDENTIFIED BY 'password';"

Write-Host "[*] Applying password reset (setting root password to 'password')..." -ForegroundColor Yellow
$proc = Start-Process "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe" `
    -ArgumentList '--defaults-file="C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"', "--init-file=$initFile", '--console' `
    -PassThru

Start-Sleep -Seconds 5
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Remove-Item $initFile -Force -ErrorAction SilentlyContinue

Write-Host "[*] Starting MySQL80 service..." -ForegroundColor Yellow
net start MySQL80

Write-Host "`n[+] SUCCESS: MySQL root password has been reset to 'password'!" -ForegroundColor Green
