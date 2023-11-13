@echo off
takeown.exe /f "C:\Windows\System32\en-US" /r /d y > NUL 2>&1
takeown.exe /f "C:\Windows\System32\SnippingTool.exe" > NUL 2>&1

del /f /q "C:\Windows\System32\en-US\SnippingTool.exe.mui" > NUL 2>&1
del /f /q "C:\Windows\System32\SnippingTool.exe" > NUL 2>&1



