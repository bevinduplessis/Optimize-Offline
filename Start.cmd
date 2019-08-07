@ECHO OFF
CD /D "%~dp0"
SET "WM_TITLE=Optimize-Offline"
SET "WM_VERSION=3.2.6.4"
TITLE %WM_TITLE% v%WM_VERSION%

REM After setting the appropriate variables and switches, run this script as an administrator to quickly call Optimize-Offline.
REM A list of all available variables and switches can be found on Optimize-Offline's GitHub Repository.

REM Set the Optimize-Offline Source Path variable.
SET "SourcePath=C:\Optimize-Offline\Win10Ent.iso"

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    ECHO Running as Administrator.
    TIMEOUT /T 2 >NUL
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -SourcePath "%SourcePath%" -WindowsApps "Whitelist" -SystemApps -Packages -Features -Win32Calc -Dedup -Registry -Additional -DaRT -ISO 
)
PAUSE
EXIT