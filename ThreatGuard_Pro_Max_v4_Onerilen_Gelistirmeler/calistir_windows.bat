@echo off
title ThreatGuard Pro Max
cd /d "%~dp0"
echo Eski Python/Flask islemleri kapatiliyor...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM py.exe >nul 2>&1
echo.
echo ThreatGuard Pro Max baslatiliyor...
echo.
echo Tarayicidan su adresi ac:
echo http://127.0.0.1:5050
echo.
python app.py
pause
