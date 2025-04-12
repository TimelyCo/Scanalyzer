@echo off
echo Scanalyzer: Static Code Analyzer
echo ============================

if not exist venv\Scripts\activate.bat (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Installing dependencies...
    pip install pylint astroid flake8 colorama antlr4-python3-runtime pytest
) else (
    call venv\Scripts\activate.bat
)

if "%1"=="" (
    echo Usage: run_scanalyzer.bat [path] [options]
    echo Example: run_scanalyzer.bat sample_code\example.py
    echo Example: run_scanalyzer.bat sample_code --output html
) else (
    python scanalyzer.py %*
)

deactivate