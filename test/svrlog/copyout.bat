echo off
set BATDIR=%~dp0
set OUTDIR=%1

if -%OUTDIR%-  == -- (
	OUTDIR=..\
)

mkdir %OUTDIR%

copy /y svrlog.exe %OUTDIR%\svrlog.exe
copy /y install.bat %OUTDIR%\install.bat
copy /y uninstall.bat %OUTDIR%\uninstall.bat
