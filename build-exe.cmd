@echo off
rem Builds ScamFilter.exe: one self-contained file that runs on any 64-bit Windows 10 or 11 PC,
rem even without .NET installed. Needs the .NET 10 SDK (https://dotnet.microsoft.com/download).
rem The finished file lands in the "publish" folder next to this script.

dotnet publish ScamFilter.Desktop\ScamFilter.Desktop.csproj -c Release -o publish
if errorlevel 1 (
    echo.
    echo Build failed. See the messages above.
    exit /b 1
)
echo.
echo Done: publish\ScamFilter.exe
