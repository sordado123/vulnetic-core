@echo off
rem ============================================================================
rem  Vulnetic - para tudo (aplicacao + banco)
rem
rem    stop.bat          para o vulnetic.exe e o container do Postgres
rem    stop.bat app      para so o vulnetic.exe (mantem o banco)
rem    stop.bat db       para so o container do Postgres
rem
rem  Os DADOS NAO sao apagados: o banco fica no volume Docker "pgdata" e o
rem  ./data (jwt.key etc) fica na pasta do projeto. Para apagar de verdade:
rem    docker compose down -v     ^(remove o volume do banco - irreversivel^)
rem ============================================================================

setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

set "WHAT=%~1"
if "%WHAT%"=="" set "WHAT=all"

echo ============================================================
echo   Vulnetic - parando (%WHAT%)
echo ============================================================
echo.

if /i "%WHAT%"=="app"  goto :onlyapp
if /i "%WHAT%"=="db"   goto :onlydb

:all
echo [*] encerrando vulnetic.exe...
taskkill /IM vulnetic.exe /F >nul 2>&1
if errorlevel 1 (echo     nenhum vulnetic.exe rodando) else (echo [+] vulnetic.exe encerrado)
goto :onlydb

:onlyapp
echo [*] encerrando vulnetic.exe...
taskkill /IM vulnetic.exe /F >nul 2>&1
if errorlevel 1 (echo     nenhum vulnetic.exe rodando) else (echo [+] vulnetic.exe encerrado)
goto :done

:onlydb
where docker >nul 2>&1
if errorlevel 1 (
	echo [!] docker nao encontrado; nada a parar no banco.
	goto :done
)
echo [*] parando o container do Postgres...
docker compose stop postgres >nul 2>&1
if errorlevel 1 (echo [!] falha ao parar o Postgres) else (echo [+] Postgres parado)
goto :done

:done
echo.
echo [i] dados preservados: volume Docker "pgdata" + pasta .\data
echo [i] para subir de novo: start-local.bat
endlocal
