@echo off
rem Build ManaKeyDumper (launcher + inject DLL) and deploy to run\
rem KEEP THIS FILE PURE ASCII + CRLF: cmd.exe runs under the GBK codepage and
rem mis-parses non-ASCII bytes, splitting lines into "not a command" errors.
setlocal
pushd "%~dp0" || exit /b 1

echo [1/3] inject DLL (NativeAOT)...
dotnet publish inject\ManaKeyDumperLib.csproj -c Release -o run\inject_build || goto :fail

echo [2/3] launcher (NativeAOT)...
dotnet publish launcher\ManaKeyDumper.csproj -c Release -o run\launcher_build || goto :fail

echo [3/3] deploy to run\...
copy /y run\inject_build\ManaKeyDumper.dll run\ >nul || goto :fail
copy /y run\launcher_build\ManaKeyDumper.exe run\ >nul || goto :fail

if not exist run\ManaKeyDumper.dll goto :fail
if not exist run\ManaKeyDumper.exe goto :fail

echo.
echo Done: run\ManaKeyDumper.exe + run\ManaKeyDumper.dll
popd
endlocal
goto :eof

:fail
echo.
echo Build failed.
echo.
echo If the error is LNK1181 (cannot open input file ... lib), the MSVC library
echo paths are missing from this shell. Set them explicitly, for example:
echo   set LIB=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\^<ver^>\lib\x64;^
echo           C:\Program Files (x86)\Windows Kits\10\Lib\^<sdk^>\um\x64;^
echo           C:\Program Files (x86)\Windows Kits\10\Lib\^<sdk^>\ucrt\x64
popd
endlocal
exit /b 1
