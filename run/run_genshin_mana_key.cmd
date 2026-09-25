@echo off
rem ============================================================
rem  GenshinManaKey - launch ManaKeyDumper (launcher asks for UAC by itself)
rem
rem  KEEP THIS FILE PURE ASCII + CRLF.
rem  If Chinese text is added, cmd.exe (GBK codepage) mis-parses it and
rem  breaks the script into "not a command" errors.
rem ============================================================
setlocal
cd /d "%~dp0"
echo Working directory: %CD%
if not exist "ManaKeyDumper.exe" (
    echo ManaKeyDumper.exe not found in %CD%
    pause
    exit /b 1
)
echo.
echo Make sure the game is closed. Then play an encrypted cutscene.
echo Keys will be written to mana_keys.log and paired_keys.json.
echo.
ManaKeyDumper.exe %*
echo.
echo Output: %CD%
echo   mana_keys.log    (raw events)
echo   paired_keys.json (filename -> aes/audio key)
pause
