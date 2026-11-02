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
rem    update_rva.cmd --new D:\Genshin\YuanShen.exe --old-rva NativeSetFile=0x070538C0
rem
rem  Exit codes reported by tools\update_rva.py:
rem    0 = success (RVAs written back, or --dry-run finished)
rem    1 = some hook was NOT migrated (source NOT changed), or you cancelled
rem    2 = bad arguments / bad environment (missing deps, no old exe, ...)
rem    3 = source WAS changed, but build.bat failed -> fix the build,
rem        do NOT re-run the migration (the old RVAs are already gone)
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
    goto :done
)
if "%RC%"=="3" (
    echo [PARTIAL] exit code 3 - RVA written back, but build.bat FAILED.
    echo           The source IS changed. Fix the build error, then rebuild.
    echo           Do NOT re-run this migration: the old RVAs are already overwritten.
    goto :done
)
if "%RC%"=="1" (
    echo [FAILED] exit code 1 - a hook was not migrated, or you cancelled.
    echo          Source NOT changed. See the messages above.
    goto :done
)
echo [FAILED] exit code %RC% - see the messages above.
echo          exit code 2 = bad arguments / environment (Python deps first).
:done
popd
pause
endlocal & exit /b %RC%
