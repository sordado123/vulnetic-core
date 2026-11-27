@echo off
rem ============================================================================
rem  Vulnetic - diagnostico rapido: o que esta rodando e em que endereco acessar
rem ============================================================================

setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

echo ============================================================
echo   Vulnetic - status
echo ============================================================
echo.

rem ---- aplicacao -----------------------------------------------------------
echo [aplicacao]
tasklist /FI "IMAGENAME eq vulnetic.exe" /NH 2>nul | find /i "vulnetic.exe" >nul
if errorlevel 1 (
	echo   vulnetic.exe : PARADO
) else (
	echo   vulnetic.exe : RODANDO
	for /f "tokens=2 delims=," %%p in ('tasklist /FI "IMAGENAME eq vulnetic.exe" /FO CSV /NH 2^>nul') do echo     pid %%p
)

rem ---- HTTP ----------------------------------------------------------------
echo.
echo [http]
powershell -NoProfile -Command ^
  "foreach($u in @('http://localhost:8787/api/health')){ try{ $r=Invoke-RestMethod $u -TimeoutSec 3; Write-Host ('  8787 : OK  ' + ($r | ConvertTo-Json -Compress)) }catch{ Write-Host '  8787 : sem resposta' } }"

rem ---- banco ---------------------------------------------------------------
echo.
echo [banco]
where docker >nul 2>&1
if errorlevel 1 (
	echo   docker : nao encontrado
) else (
	docker info >nul 2>&1
	if errorlevel 1 (
		echo   docker : daemon PARADO ^(abra o Docker Desktop^)
	) else (
		rem container name intentionally NOT renamed: Docker Compose derives the
		rem project prefix from this folder's name (still "ARTEX" on disk).
		for /f "delims=" %%s in ('docker ps --filter "name=artex-postgres" --format "{{.Status}}" 2^>nul') do echo   container : %%s
		for /f "delims=" %%p in ('docker port artex-postgres-1 2^>nul') do echo   porta     : %%p
	)
)

rem ---- enderecos -----------------------------------------------------------
echo.
echo [como acessar]
echo   neste PC        : http://localhost:8787
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\show-urls.ps1"

echo.
echo [i] iniciar: start-local.bat    parar: stop.bat
endlocal
