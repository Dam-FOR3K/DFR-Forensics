@echo off
chcp 65001 > nul
echo ==============================================================================
echo  DFR-Forensics - Installation Hors-Ligne (Air-Gapped)
echo ==============================================================================
echo.
echo [*] Installation des paquets depuis le dossier local wheels/ sans accès Internet...
python -m pip install --no-index --find-links=wheels -r requirements.txt

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Tous les paquets ont été installés avec succès !
    echo Vous pouvez maintenant lancer l'application avec run_gui.bat ou main.py
) else (
    echo.
    echo [ERREUR] L'installation a échoué. Vérifiez que Python est bien dans votre PATH.
)
pause
