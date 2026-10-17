@echo off
rem Opens the gateway dashboard on Windows: double-click this file.
cd /d "%~dp0.."
where node >nul 2>nul || (echo Node.js 18 or newer is required: https://nodejs.org & pause & exit /b 1)
node dashboard\dashboard.js %*
if errorlevel 1 pause
