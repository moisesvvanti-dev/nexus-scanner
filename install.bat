@echo off
title Reparador de Execucao CyberStrikeAI - Automatico
:: Verifica se esta rodando como administrador
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Rodando com privilegios de Administrador.
) else (
    echo [ERRO] Por favor, execute este script como ADMINISTRADOR.
    pause
    exit
)

echo ------------------------------------------------------
echo INICIANDO REPARO DE COMPATIBILIDADE E PERMISSOES
echo ------------------------------------------------------

echo [1/5] Desbloqueando arquivos na pasta atual...
powershell -Command "Get-ChildItem -Recurse | Unblock-File"

echo [2/5] Resetando permissoes de acesso total (ACLs)...
icacls . /grant Todos:(OI)(CI)F /T /C

echo [3/5] Corrigindo arquivos de sistema corrompidos (SFC)...
sfc /scannow

echo [4/5] Reparando a imagem do Windows (DISM)...
dism /online /cleanup-image /restorehealth

echo [5/5] Limpando cache do Windows Store e Execucao...
wsreset.exe

echo ------------------------------------------------------
echo VERIFICACAO DE ARQUITETURA:
systeminfo | findstr /C:"Tipo de sistema"
echo Se aparecer 'x86-based PC' e seu programa for 64-bits, ele NUNCA vai rodar.
echo Se aparecer 'x64-based PC', o erro deve estar resolvido.
echo ------------------------------------------------------
echo REPARO CONCLUIDO! Tente rodar o programa agora.
pause