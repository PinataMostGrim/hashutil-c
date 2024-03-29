:: Build script for 'test-shared-library'

:: Requirements:
::  - MSVC accessible via PATH
::  - "vcvarsall.bat x64" must be executed in the shell before this script is run
::  - This script must be run from project root folder


@echo off

:: NOTE: Set %DEBUG% to 1 for debug build
set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4996 -wd4201 -DHASHUTIL_SLOW=1 -Zi -DEBUG:FULL

set BuildFolder=bin
:: set LinkerFlags=-incremental:no

pushd %BuildFolder%

:: Successfully build an stb-style header and call it in a C++ program
cl %CompilerFlags% -Tc "..\src\md5.h" -DHASHUTIL_MD5_IMPLEMENTATION -Femd5.dll /link -DLL %LinkerFlags% -EXPORT:MD5_GetVersion -EXPORT:MD5_HashString -EXPORT:MD5_HashFile
cl -nologo -Gm- -Zi -FC -Tc "..\src\sha1.h" -DHASHUTIL_SHA1_IMPLEMENTATION -Fesha1.dll -Fmsha1.map /link -DLL -incremental:no -PDB:sha1.pbd -EXPORT:SHA1_GetVersion -EXPORT:SHA1_HashString -EXPORT:SHA1_HashFile
cl -nologo -Gm- -Zi -FC -Tc "..\src\sha2.h" -DHASHUTIL_SHA2_IMPLEMENTATION -Fesha2.dll -Fmsha2.map /link -DLL -incremental:no -PDB:sha2.pbd -EXPORT:SHA2_GetVersion -EXPORT:SHA2_HashStringSHA224 -EXPORT:SHA2_HashStringSHA256 -EXPORT:SHA2_HashStringSHA384 -EXPORT:SHA2_HashStringSHA512 -EXPORT:SHA2_HashStringSHA512_224 -EXPORT:SHA2_HashStringSHA512_256

cl -nologo -Gm- -Zi -FC -Tc "..\src\test-shared-library.c" /link
test-shared-library

popd
