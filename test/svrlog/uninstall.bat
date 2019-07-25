echo off
set BATDIR=%~dp0
set OUTDIR=%1

if -%OUTDIR%-  == -- (
	set OUTDIR=%WINDIR%\System32
)


sc config idvtools depend= /
sc stop idvtools
sc stop svrlog
sc delete svrlog
del %OUTDIR%\svrlog.exe