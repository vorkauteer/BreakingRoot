cmake_minimum_required(VERSION 3.24)
project(breakingroot LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(breakingroot
    src/main.cpp
    src/app.cpp
    src/command.cpp
    src/lsass_advanced.cpp
    src/defense.cpp
    src/recon_modules.cpp
    src/bypass.cpp
    src/driver_byovd.cpp
    src/creds_sam.cpp
)

target_link_libraries(breakingroot PRIVATE 
    advapi32 
    dbghelp 
    crypt32 
    netapi32 
    ntdll 
    userenv
    psapi  # Добавлено для EnumDeviceDrivers
)

target_include_directories(breakingroot PRIVATE include)

if (WIN32)
    target_compile_definitions(breakingroot PRIVATE UNICODE _UNICODE _CONSOLE)
endif()

if (MSVC)
    target_compile_options(breakingroot PRIVATE /W3 /permissive-)
endif()

# Добавляем определение _CRT_SECURE_NO_WARNINGS для всего проекта
target_compile_definitions(breakingroot PRIVATE _CRT_SECURE_NO_WARNINGS)