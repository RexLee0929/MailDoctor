@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"

set "PYEXE="
where python >nul 2>nul && set "PYEXE=python"
if not defined PYEXE (
  where py >nul 2>nul && set "PYEXE=py -3"
)
if not defined PYEXE (
  echo.
  echo   没有找到 Python 3。
  echo   请先安装 https://www.python.org/downloads/ ，安装时勾选 Add to PATH。
  echo.
  pause
  exit /b 1
)

echo.
echo   MailDoctor 正在启动，浏览器会自动打开...
echo   关闭这个窗口即可停止服务。
echo.

%PYEXE% run.py --open
pause
