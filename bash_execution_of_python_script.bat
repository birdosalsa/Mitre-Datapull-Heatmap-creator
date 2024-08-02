@echo off

REM Check for Python
echo Checking for Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Please install Python.
    pause
    exit /b
) else (
    echo Python is installed.
)
pause

REM Check for pip and install if not present
echo Checking for pip...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo pip is not installed. Attempting to install pip...
    python -m ensurepip
    if %errorlevel% neq 0 (
        echo Failed to install pip. Exiting.
        pause
        exit /b
    )
    python -m pip install --upgrade pip
    echo pip installed successfully.
) else (
    echo pip is installed.
)
pause

REM Install required Python packages
echo Installing required Python packages...
python -m pip install pandas
python -m pip install numpy
python -m pip install scipy
python -m pip install networkx
python -m pip install matplotlib
python -m pip install seaborn
python -m pip install bs4
python -m pip install httpx
echo All required packages have been installed.
pause

REM Run the Python script
echo Running the Python script...
python mitre_scrapping_data_retrieval.py

pause