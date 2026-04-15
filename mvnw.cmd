@echo off
setlocal

set "MAVEN_VERSION=3.9.6"
set "MAVEN_HOME=%~dp0.maven\apache-maven-%MAVEN_VERSION%"
set "MAVEN_CMD=%MAVEN_HOME%\bin\mvn.cmd"

REM --- Detecter JAVA_HOME ---
if not defined JAVA_HOME (
    for /f "delims=" %%i in ('where java 2^>nul') do (
        for %%p in ("%%~dpi..") do set "JAVA_HOME=%%~fp"
        goto :found_java
    )
    REM Chercher dans les extensions VS Code
    for /d %%d in ("%USERPROFILE%\.vscode\extensions\redhat.java-*") do (
        for /d %%j in ("%%d\jre\*") do (
            if exist "%%j\bin\java.exe" (
                set "JAVA_HOME=%%j"
                set "PATH=%%j\bin;%PATH%"
                goto :found_java
            )
        )
    )
    echo [ERREUR] Java introuvable. Installez JDK 17+.
    exit /b 1
)
:found_java

REM --- Telecharger Maven si absent ---
if not exist "%MAVEN_CMD%" (
    echo ============================================
    echo   Telechargement automatique de Maven %MAVEN_VERSION%...
    echo ============================================
    if not exist "%~dp0.maven" mkdir "%~dp0.maven"
    powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://archive.apache.org/dist/maven/maven-3/%MAVEN_VERSION%/binaries/apache-maven-%MAVEN_VERSION%-bin.zip' -OutFile '%~dp0.maven\maven.zip'"
    if errorlevel 1 (
        echo [ERREUR] Echec du telechargement de Maven.
        exit /b 1
    )
    powershell -NoProfile -Command "Expand-Archive -Path '%~dp0.maven\maven.zip' -DestinationPath '%~dp0.maven' -Force"
    del "%~dp0.maven\maven.zip" 2>nul
    echo Maven %MAVEN_VERSION% installe avec succes.
    echo.
)

REM --- Executer Maven ---
"%MAVEN_CMD%" %*
