@echo off
Title .NET Framework 3.5 Offline Installer
for %%I in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist "%%I:\\sources\install.wim" set setupdrv=%%I
if defined setupdrv (
echo Found drive %setupdrv%
echo Installing .NET Framework 3.5...
Dism /online /enable-feature /featurename:NetFX3 /All /Source:%setupdrv%:\sources\sxs /LimitAccess
echo.
echo .NET Framework 3.5 should be installed
echo.
) else (
echo No installation media found!
echo Insert DVD or USB flash drive and run this file once again. 
echo.
)
pause