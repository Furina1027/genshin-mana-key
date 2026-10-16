@echo off
rem ============================================================
rem  GenshinManaKey - launch ManaKeyDumper
rem
rem  KEEP THIS FILE PURE ASCII + CRLF.
rem  If Chinese text is added, cmd.exe (GBK codepage) mis-parses it and
rem  breaks the script into "not a command" errors.
rem
rem  This window closes immediately: the launcher is a GUI app (WinExe) and
rem  shows its own overlay at the bottom-left of the game window.
rem  Debug console: set GMK_CONSOLE=1  Overlay off: set GMK_OVERLAY=0
rem
rem  Overlay style (optional): GMK_OVERLAY_TEXT_COLOR / GMK_OVERLAY_SHADOW_COLOR /
rem    GMK_OVERLAY_MONO_FONT / GMK_OVERLAY_CJK_FONT / GMK_OVERLAY_FONT_FILE
rem  Same font as BetterGI: drop MiSans-Regular.ttf next to ManaKeyDumper.exe
rem ============================================================
setlocal
cd /d "%~dp0"
if not exist "ManaKeyDumper.exe" (
    echo ManaKeyDumper.exe not found in %CD%
    pause
    exit /b 1
)
echo Starting ManaKeyDumper (UAC prompt may follow)...
start "" "%~dp0ManaKeyDumper.exe" %*
endlocal
exit /b 0
