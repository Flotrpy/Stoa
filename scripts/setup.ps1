$ErrorActionPreference = "Stop"

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentPath = Join-Path $RepositoryRoot ".venv"
$RequiredPython = "3.12"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$CommandArguments
    )
    & $Executable @CommandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $Executable $CommandArguments"
    }
}

Push-Location $RepositoryRoot
try {
    $Detected = (& python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')").Trim()
    if ($Detected -ne $RequiredPython) {
        throw "Python $RequiredPython is required; detected $Detected. Install Python $RequiredPython and ensure 'python' is on PATH."
    }

    if (-not (Test-Path -LiteralPath $EnvironmentPath)) {
        Invoke-Checked python @("-m", "venv", $EnvironmentPath)
    }

    $EnvironmentPython = Join-Path $EnvironmentPath "Scripts\python.exe"
    Invoke-Checked $EnvironmentPython @("-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "pip==26.2.1")
    Invoke-Checked $EnvironmentPython @("-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements/dev.txt")
    Invoke-Checked $EnvironmentPython @("-m", "pip", "install", "--disable-pip-version-check", "--editable", ".", "--no-deps")
    Write-Host "Stoa development environment is ready."
}
finally {
    Pop-Location
}
