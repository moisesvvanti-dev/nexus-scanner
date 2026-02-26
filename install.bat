@echo off
setlocal
title [NEXUS ULTIMA] - Dependency Auto-Installer v21.0
color 0a

echo =======================================================
echo          PENTESTGPT - NEXUS ULTIMA INSTALLER
echo =======================================================
echo.
echo [!] Iniciando a instalacao REAL das dependencias do sistema...
echo [!] Por favor, aguarde. Este processo ira baixar as bibliotecas pesadas.
echo.

:: 1. Checagem do Python e PIP
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0c
    echo [ERROR] O Python 3 nao foi encontrado no seu sistema.
    echo [!] Instale o Python 3.10+ e marque a caixa "Add Python to PATH".
    pause
    exit /b
)

echo [*] Atualizando o construtor global (PIP)...
python -m pip install --upgrade pip >nul 2>&1

:: 2. Instalacao das Bibliotecas no requirements.txt
if exist "requirements.txt" (
    echo [*] Lendo e instalando modulos de rede, interface e motores assincronos...
    echo [*] (Isso PODE DEMORAR alguns minutos dependendo da sua internet)
    echo.
    python -m pip install -r requirements.txt
    
    if %errorlevel% neq 0 (
        color 0e
        echo.
        echo [WARNING] Ocorreram alguns avisos durante o download.
        echo [!] Verifique acima se houve falha critica de conectividade.
    ) else (
        echo.
        echo [+] Modulos principais instalados com sucesso no seu Python!
    )
) else (
    color 0c
    echo [ERROR] Arquivo "requirements.txt" nao foi encontrado na pasta atual!
    pause
    exit /b
)

:: 3. Instalacao do Motor Fantasma (Playwright)
echo.
echo [*] Configurando os binarios do navegador Headless invisivel (Playwright)...
python -m playwright install --with-deps >nul 2>&1
echo [+] Arquitetura invisivel Phantom do browser acoplada.

echo.
echo =======================================================
echo [+] Installation Completed Successfully!
echo [+] O seu Arsenal Nexus V21 esta pronto para operar.
echo =======================================================
echo.
echo - Para iniciar a interface grafica agora, feche esta janela 
echo   e execute o comando: python main.py
echo.
pause
