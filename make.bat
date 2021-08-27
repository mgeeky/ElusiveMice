@echo off

set PLAT="x86"
echo Building Platform %PLAT%
call cc.bat ReflectiveLoader

set PLAT="x64"
echo Building Platform %PLAT%
call cc.bat ReflectiveLoader

echo Compiled.