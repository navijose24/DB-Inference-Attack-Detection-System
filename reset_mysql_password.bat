@echo off
echo [*] Stopping MySQL80 service...
net stop MySQL80

echo ALTER USER 'root'@'localhost' IDENTIFIED BY 'password'; > "C:\mysql_pass_reset.txt"

echo [*] Resetting root password to 'password'...
start "" "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe" --defaults-file="C:\ProgramData\MySQL\MySQL Server 8.0\my.ini" --init-file="C:\mysql_pass_reset.txt" --console

timeout /t 5 /nobreak >nul
taskkill /f /im mysqld.exe >nul 2>&1
del "C:\mysql_pass_reset.txt" >nul 2>&1

echo [*] Starting MySQL80 service...
net start MySQL80

echo.
echo ========================================================
echo [+] SUCCESS: MySQL root password is now set to: password
echo ========================================================
pause
