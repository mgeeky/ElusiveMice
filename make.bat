@echo off

set MSVC_PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.28.29910\bin\Hostx64

set INCL_UM="%ProgramFiles(x86)%\Windows Kits\10\Include\10.0.22000.0\um"
set INCL_SHARED="%ProgramFiles(x86)%\Windows Kits\10\Include\10.0.22000.0\shared"
set INCL_UCRT="%ProgramFiles(x86)%\Windows Kits\10\Include\10.0.22000.0\ucrt"

set OUT=ReflectiveLoader

echo Building Platform x86...
"%MSVC_PATH%\x86\cl.exe" /GS- /nologo /Ob1 /c /I%INCL_UM% /I%INCL_SHARED% /I%INCL_UCRT% src\%OUT%.c /Fobin\%OUT%.x86.o

echo.
echo Building Platform x64...
"%MSVC_PATH%\x64\cl.exe" /GS- /nologo /Ob1 /c /I%INCL_UM% /I%INCL_SHARED% /I%INCL_UCRT% src\%OUT%.c /Fobin\%OUT%.x64.o

echo.
echo Compiled.

echo.
for %%F IN (bin\*.o) DO echo %%F && "%MSVC_PATH%\x64\dumpbin.exe" /summary %%F | findstr .text