:: IMPORTANT: "vcvarsall.bat x64" must be executed in the shell first. Must be run from project root folder.

@echo off

:: NOTE: Set %DEBUG% to 1 for debug build
set CompilerFlags=-nologo -Od -Gm- -MT -GR- -EHa- -Oi -W4 -FC -wd4996 -wd4201 -DHASHUTIL_SLOW=1 -Zi -DEBUG:FULL

set BuildFolder=bin
:: set LinkerFlags=-incremental:no

pushd %BuildFolder%

:: Successfully build an stb-style header and call it in a C++ program
cl %CompilerFlags% -Tc "..\src\md5.h" -DHASHUTIL_MD5_IMPLEMENTATION -Femd5.dll /link -DLL %LinkerFlags% -EXPORT:MD5GetVersion -EXPORT:MD5HashString -EXPORT:MD5HashFile
cl -nologo -Gm- -Zi -FC -Tc "..\src\sha1.h" -DHASHUTIL_SHA1_IMPLEMENTATION -Fesha1.dll -Fmsha1.map /link -DLL -incremental:no -PDB:sha1.pbd -EXPORT:SHA1GetVersion -EXPORT:SHA1HashString -EXPORT:SHA1HashFile
cl -nologo -Gm- -Zi -FC -Tc "..\src\sha2.h" -DHASHUTIL_SHA2_IMPLEMENTATION -Fesha2.dll -Fmsha2.map /link -DLL -incremental:no -PDB:sha2.pbd -EXPORT:SHA2_GetVersion -EXPORT:SHA2_HashStringSHA224 -EXPORT:SHA2_HashStringSHA256 -EXPORT:SHA2_HashStringSHA384 -EXPORT:SHA2_HashStringSHA512 -EXPORT:SHA2_HashStringSHA512_224 -EXPORT:SHA2_HashStringSHA512_256

cl -nologo -Gm- -Zi -FC -Tc "..\src\test_shared_library.c" /link
test_shared_library

popd
