
cmake_minimum_required(VERSION 3.0)
project(tstsql3)

#set(SQLite3_INCLUDE_DIR F:\\vcpkg\\packages\\sqlite3_x64-windows\\include)
#set(SQLite3_LIBRARY_DIR F:\\vcpkg\\packages\\sqlite3_x64-windows\\bin)
#set(SQLite3_LIBRARY sqlite3.dll)

find_package(SQLite3 3.7.17 REQUIRED)

add_executable(tstsql3 main.cpp)
target_link_libraries(tstsql3 sqlite3)