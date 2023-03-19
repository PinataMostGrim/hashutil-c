:: IMPORTANT: "vcvarsall.bat x64" must be executed in the shell first. Must be run from project root folder.

@echo off

:: NOTE: Set %DEBUG% to 1 for debug build
IF [%DEBUG%] == [1] (
    :: Making debug build
    set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4505 -wd4068 -wd4996 -wd4201 -DHASHUTIL_SLOW=1 -Zi -DEBUG:FULL
) ELSE (
    :: Making release build
    set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4505 -wd4068 -wd4996 -wd4201
)

set BuildFolder=bin
set LinkerFlags=-opt:ref

:: Create build folder if it doesn't exist and change working directory
IF NOT EXIST %BuildFolder% mkdir %BuildFolder%
pushd %BuildFolder%

:: Compile test runner
del *.pdb > NUL 2> NUL
cl %CompilerFlags% "..\src\test-hashutil.cpp" /link %LinkerFlags%
popd
