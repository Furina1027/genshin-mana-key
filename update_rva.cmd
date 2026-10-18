@echo off
rem ============================================================
rem  GenshinManaKey - update hook RVAs after a game update
rem
rem  Double-click this file, or drag the NEW YuanShen.exe onto it.
rem
rem  It needs the PREVIOUS version's exe as a reference:
rem    rva_cache\YuanShen.exe  (cached automatically after each
rem    successful run - keep that folder around!)
rem
rem  Workflow: game updated -> the new exe is already installed ->
rem  double-click this -> confirm -> build.bat to rebuild/deploy.
rem
rem  Extra args are passed to tools\update_rva.py, e.g.
rem    update_rva.cmd --yes --build
rem
rem  KEEP THIS FILE PURE ASCII + CRLF: cmd.exe (GBK codepage) would
rem  mis-parse non-ASCII bytes and break the script.
rem ============================================================
setlocal
pushd "%~dp0" || exit /b 1
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo [ERROR] Python not found in PATH. Install Python 3.8+ and retry.
    echo.
    popd
    pause
    endlocal & exit /b 2
)
python "tools\update_rva.py" %*
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (
    echo [OK] RVA updated.
) else (
    echo [FAILED] exit code %RC% - see the messages above. Source NOT changed.
)
popd
pause
endlocal & exit /b %RC%