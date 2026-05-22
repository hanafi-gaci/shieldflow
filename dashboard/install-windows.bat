@echo off
:: ShieldFlow Agent — Installation Windows
:: Usage: install-windows.bat TENANT_ID AGENT_KEY

setlocal enabledelayedexpansion

set TENANT_ID=%1
set AGENT_KEY=%2
set SERVER=https://shieldflow-rfzv.onrender.com

if "%TENANT_ID%"=="" (
    echo [ERROR] Usage: install-windows.bat TENANT_ID AGENT_KEY
    pause
    exit /b 1
)

echo.
echo  _____ _     _      _     _ _____ _
echo /  ___| |   (_)    | |   | |  ___| |
echo \ `--.| |__  _  ___| | __| | |_  | | _____      __
echo  `--. \ '_ \| |/ _ \ |/ _` |  _| | |/ _ \ \ /\ / /
echo /\__/ / | | | |  __/ | (_| | |   | | (_) \ V  V /
echo \____/|_| |_|_|\___|_|\__,_\_|   |_|\___/ \_/\_/
echo.
echo  Installation Agent Windows
echo  Serveur: %SERVER%
echo.

:: Verifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Python non detecte. Installation en cours...
    :: Telecharger Python via winget
    winget install Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo [ERROR] Impossible d'installer Python automatiquement.
        echo [INFO] Installez Python depuis https://python.org puis relancez ce script.
        pause
        exit /b 1
    )
)

echo [OK] Python detecte

:: Creer dossier
if not exist "%USERPROFILE%\shieldflow" mkdir "%USERPROFILE%\shieldflow"
cd /d "%USERPROFILE%\shieldflow"

:: Installer dependances
echo [INFO] Installation des dependances...
pip install psutil requests --quiet --break-system-packages 2>nul || pip install psutil requests --quiet

:: Telecharger agent
echo [INFO] Telechargement de l'agent...
curl -sSL %SERVER%/agent/agent_v2.py -o agent_v2.py
curl -sSL %SERVER%/agent/expert_checks.py -o expert_checks.py

:: Creer fichier de config
echo SHIELDFLOW_SERVER=%SERVER% > .env
echo SHIELDFLOW_TENANT=%TENANT_ID% >> .env
echo SHIELDFLOW_KEY=%AGENT_KEY% >> .env

:: Creer script de lancement
echo @echo off > run_agent.bat
echo cd /d "%%USERPROFILE%%\shieldflow" >> run_agent.bat
echo set SHIELDFLOW_SERVER=%SERVER% >> run_agent.bat
echo set SHIELDFLOW_TENANT=%TENANT_ID% >> run_agent.bat
echo set SHIELDFLOW_KEY=%AGENT_KEY% >> run_agent.bat
echo python agent_v2.py >> run_agent.bat

:: Installer comme service au demarrage via Task Scheduler
echo [INFO] Installation du service de demarrage automatique...
schtasks /create /tn "ShieldFlow Agent" /tr "\"%USERPROFILE%\shieldflow\run_agent.bat\"" /sc onlogon /ru "%USERNAME%" /f >nul 2>&1

if errorlevel 1 (
    echo [WARN] Service automatique non installe. L'agent doit etre lance manuellement.
) else (
    echo [OK] Agent configure pour demarrer automatiquement
)

:: Demarrer l'agent maintenant
echo [INFO] Demarrage de l'agent ShieldFlow...
start /b "" python agent_v2.py

echo.
echo ================================================================
echo  ShieldFlow Agent installe avec succes !
echo  L'agent surveille cette machine 24h/24.
echo  Il demarrera automatiquement a chaque connexion Windows.
echo ================================================================
echo.
pause
