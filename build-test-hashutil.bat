:: Build script for 'test-hashutil'

:: Requirements:
::  - MSVC accessible via PATH
::  - "vcvarsall.bat x64" must be executed in the shell before this script is run
::  - This script must be run from project root folder


@echo off

:: Set a variable for tracking build failure
set "BUILD_FAILED="

:: NOTE: Set %DEBUG% to 1 for debug build
IF [%DEBUG%] == [1] (
    :: Making debug build
    set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4505 -wd4068 -wd4996 -wd4201 -DHASHUTIL_SLOW=1 -Zi -DEBUG:FULL -analyze
) ELSE (
    :: Making release build
    set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4505 -wd4068 -wd4996 -wd4201 -analyze
)

set BuildFolder=bin
set LinkerFlags=-opt:ref

:: Create build folder if it doesn't exist and change working directory
IF NOT EXIST %BuildFolder% mkdir %BuildFolder%
pushd %BuildFolder%

:: Compile test runner
del *.pdb > NUL 2> NUL
cl %CompilerFlags% "..\src\test-hashutil.c" /link %LinkerFlags%
if %ERRORLEVEL% neq 0 (set "BUILD_FAILED=false")
popd

:: Exit with error if compiling fails
if defined BUILD_FAILED (exit /b 1 )
