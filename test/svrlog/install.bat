echo off
set BATDIR=%~dp0
set OUTDIR=%1

if -%OUTDIR%-  == -- (
	set OUTDIR=%WINDIR%\System32
)


mkdir %OUTDIR%
copy /y %BATDIR%\svrlog.exe %OUTDIR%\svrlog.exe
sc create svrlog binpath= "%OUTDIR%\svrlog.exe server -vvvvv -a %OUTDIR%\svrlog_app.log -f %OUTDIR%\svrlog_out.log" start= demand
sc config idvtools depend= svrlog
