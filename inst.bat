pushd C:\WinDDK\7600.16385.0
call C:\WinDDK\7600.16385.0\bin\setenv C:\WinDDK\7600.16385.0 fre wnet
popd
copy T:\mat\Projects\ResearchTools\Console\xGetOpt\XGetopt.* .
copy T:\mat\Projects\ResearchTools\String\StringToArgumentList\StringToArgumentList.* .
set DBGSDK_INC_PATH=T:\mat\Projects\Lib\windbg\sdk\inc
set DBGSDK_LIB_PATH=T:\mat\Projects\Lib\windbg\sdk\lib
set DBGLIB_LIB_PATH=T:\mat\Projects\Lib\windbg\sdk\lib
REM set SDK_INC_PATH="C:\Program Files\Microsoft Visual Studio 9.0\VC\INCLUDE"
REM set SDK_INC_PATH="C:\Program Files\Microsoft Visual Studio 9.0\VC\INCLUDE"
REM C:\Program Files\Microsoft Visual Studio 9.0\VC\ATLMFC\INCLUDE
REM C:\Program Files\Microsoft Visual Studio 9.0\VC\INCLUDE
REM C:\Program Files\Microsoft SDKs\Windows\v6.0A\include
REM C:\Program Files\Microsoft Visual Studio .NET 2003\SDK\v1.1\include\
build -cZMg
dir i386\*.dll
copy i386\*.dll  "C:\Program Files\Debugging Tools for Windows (x86)\winext"
pause
