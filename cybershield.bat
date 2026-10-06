@echo off
rem CyberShield AI - Orizon Studio
rem Uso: doble clic (menu interactivo) o "cybershield.bat <comando> <args>"
setlocal EnableDelayedExpansion
cd /d "%~dp0"
set "PHP=C:\xampp\php\php.exe"
if not exist "%PHP%" set "PHP=php"

rem Si hay argumentos -> modo comando directo
if not "%~1"=="" (
    "%PHP%" "%~dp0cybershield.php" %*
    goto :end
)

rem ── Modo interactivo ────────────────────────────────
:menu
cls
echo.
echo   ================================================
echo    CYBERSHIELD AI - Auditor de Seguridad
echo    Orizon Studio
echo   ================================================
echo.
echo    1) Auditoria completa de un proyecto (code+sys)
echo    2) Analizar access log (buscar ataques)
echo    3) Solo auditoria de codigo
echo    4) Solo auditoria de servidor/docroot
echo    5) Abrir ultimo informe HTML
echo    6) REPARAR proyecto (htaccess + cuarentena)
echo    0) Salir
echo.
set /p "OP=  Elige opcion: "

if "%OP%"=="0" exit /b 0
if "%OP%"=="5" goto :openreport

set /p "TARGET=  Ruta del proyecto o fichero de log: "
if "%TARGET%"=="" goto :menu

set "STAMP=%DATE:~6,4%%DATE:~3,2%%DATE:~0,2%-%TIME:~0,2%%TIME:~3,2%"
set "STAMP=%STAMP: =0%"
if not exist "%~dp0informes" mkdir "%~dp0informes"
set "REPORT=%~dp0informes\auditoria-%STAMP%.html"

if "%OP%"=="1" "%PHP%" "%~dp0cybershield.php" all "%TARGET%" --html "%REPORT%"
if "%OP%"=="2" "%PHP%" "%~dp0cybershield.php" log "%TARGET%"
if "%OP%"=="3" "%PHP%" "%~dp0cybershield.php" code "%TARGET%" --html "%REPORT%"
if "%OP%"=="4" "%PHP%" "%~dp0cybershield.php" sys "%TARGET%" --html "%REPORT%"
if "%OP%"=="6" "%PHP%" "%~dp0cybershield.php" fix "%TARGET%"

echo.
if exist "%REPORT%" (
    set /p "OPEN=  Abrir informe HTML en el navegador? [S/n]: "
    if /i not "!OPEN!"=="n" start "" "%REPORT%"
)
pause
goto :menu

:openreport
for /f "delims=" %%f in ('dir /b /o-d "%~dp0informes\*.html" 2^>nul') do (
    start "" "%~dp0informes\%%f"
    goto :menu
)
echo   No hay informes todavia.
pause
goto :menu

:end
endlocal
