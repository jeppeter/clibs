to make cmake ok will add 
SQLITE_INST_DIR=F:\vcpkg\packages\sqlite3_x64-windows
INCLUDE=%INCLUDE%;%SQLITE_INST_DIR%\include

cmake -B build -DCMAKE_PREFIX_PATH=%SQLITE_INST_DIR%

to edit file tstsql3.vcxproj

<AdditionalLibraryDirectories>F:\vcpkg\packages\sqlite3_x64-windows\lib;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>


copy F:\vcpkg\packages\sqlite3_x64-windows\bin\sqlite3.dll to .\build\Release to run ok

