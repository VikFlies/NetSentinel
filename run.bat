@echo off
chcp 65001 >nul 2>&1
echo.
echo ================================================================
echo   NetSentinel - Analyseur de logs ^& Detecteur d'intrusion
echo ================================================================
echo.

REM --- Trouver le mvnw.cmd local ---
if exist "%~dp0mvnw.cmd" (
    set "MVN=%~dp0mvnw.cmd"
) else (
    where mvn >nul 2>&1
    if errorlevel 1 (
        echo [ERREUR] Maven introuvable. Lancez d'abord : mvnw.cmd
        pause
        exit /b 1
    )
    set "MVN=mvn"
)

echo Compilation...
call %MVN% -q compile -DskipTests

if errorlevel 1 (
    echo [ERREUR] Echec de la compilation.
    pause
    exit /b 1
)

echo Lancement de NetSentinel...
echo.
call %MVN% -q exec:java -Dexec.mainClass="com.netsentinel.Main"
pause
