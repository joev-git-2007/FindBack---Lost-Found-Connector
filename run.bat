@echo off
echo ================================
echo   FindBack - Lost and Found App
echo ================================
echo.

REM Detect Python
where py >nul 2>&1
if %errorlevel%==0 (
    set PYTHON=py
) else (
    where python >nul 2>&1
    if %errorlevel%==0 (
        set PYTHON=python
    ) else (
        echo ERROR: Python not found. Install from https://python.org
        pause
        exit
    )
)

echo Installing dependencies...
%PYTHON% -m pip install -r requirements.txt --quiet
echo Done!
echo.

REM !! CHANGE THIS to a strong secret before sharing the app !!
set ADMIN_SECRET=findback-admin-2024

REM CORS origin
set ALLOWED_ORIGIN=http://localhost:8000

echo Admin panel secret: %ADMIN_SECRET%
echo Starting server at http://localhost:8000
echo DO NOT close this window while using the app.
echo Press Ctrl+C to stop.
echo.
timeout /t 1 >nul
start "" "http://localhost:8000"
%PYTHON% -m uvicorn main:app --port 8000
pause
