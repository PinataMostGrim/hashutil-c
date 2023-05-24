:: Build script for 'hashutil'

:: Requirements:
::  - MSVC accessible via PATH
::  - "vcvarsall.bat x64" must be executed in the shell before this script is run
::  - This script must be run from project root folder

@echo off

:: NOTE: Set %DEBUG% to 1 for debug build
IF [%DEBUG%] == [1] (
    :: Making debug build
    set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4996 -wd4201 -DHASHUTIL_SLOW=1 -Zi -DEBUG:FULL -analyze
) ELSE (
    :: Making release build
    set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4996 -wd4201 -DHASHUTIL_SLOW=0 -analyze
)

set BuildFolder=bin
set LinkerFlags=-opt:ref -incremental:no

:: Create build folder if it doesn't exist and change working directory
IF NOT EXIST %BuildFolder% mkdir %BuildFolder%
pushd %BuildFolder%

:: Compile test runner
del *.pdb > NUL 2> NUL
cl %CompilerFlags% -Tc "..\src\md5.h" -DHASHUTIL_MD5_IMPLEMENTATION -Femd5.dll /link -DLL %LinkerFlags% -EXPORT:MD5_GetVersion -EXPORT:MD5_HashString -EXPORT:MD5_HashFile
cl %CompilerFlags% -Tc "..\src\sha1.h" -DHASHUTIL_SHA1_IMPLEMENTATION -Fesha1.dll /link -DLL %LinkerFlags% -EXPORT:SHA1_GetVersion -EXPORT:SHA1_HashString -EXPORT:SHA1_HashFile
cl %CompilerFlags% -Tc "..\src\sha2.h" -DHASHUTIL_SHA2_IMPLEMENTATION -Fesha2.dll /link -DLL %LinkerFlags% -EXPORT:SHA2_GetVersion -EXPORT:SHA2_HashStringSHA256
cl %CompilerFlags% "..\src\hashutil.c" /link %LinkerFlags%
popd
