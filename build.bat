@echo off
rem Build ManaKeyDumper (launcher + inject DLL) and deploy to runsetlocal
cd /d %~dp0

echo [1/2] inject DLL...
dotnet publish inject\ManaKeyDumperLib.csproj -c Release -o run\inject_build || goto :fail

echo [2/2] launcher...
dotnet publish launcher\ManaKeyDumper.csproj -c Release -o run\launcher_build || goto :fail

copy /y run\inject_build\ManaKeyDumper.dll run\ >nul
copy /y run\launcher_build\ManaKeyDumper.exe run\ >nul

echo.
echo Done: run\ManaKeyDumper.exe + run\ManaKeyDumper.dll
goto :eof

:fail
echo Build failed
exit /b 1
