@echo off
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe

if not exist "%CSC%" (
    echo Could not find csc.exe at %CSC%
    echo If you are on 64-bit Windows and only have the Framework64 compiler,
    echo try: %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
    pause
    exit /b 1
)

"%CSC%" /nologo /target:winexe /out:KeepAwake.exe ^
    /reference:System.Windows.Forms.dll ^
    /reference:System.Drawing.dll ^
    /resource:KeepAwake.ico ^
    /resource:KeepAwake_off.ico ^
    /win32icon:KeepAwake.ico ^
    KeepAwake.cs

if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo Build succeeded: KeepAwake.exe
pause
