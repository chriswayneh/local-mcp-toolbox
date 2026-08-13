param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("install", "doctor", "serve", "test", "lint", "format", "typecheck", "audit", "docs-validate", "package-build", "sbom", "compose-validate", "docker-build", "docker-doctor")]
    [string]$Task
)

$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
$toolbox = Join-Path $PSScriptRoot "..\.venv\Scripts\local-mcp-toolbox.exe"
$docker = "docker"

function Invoke-Checked {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Task) {
    "install" { Invoke-Checked $python @("-m", "pip", "install", "-e", ".[dev,docker]") }
    "doctor" { Invoke-Checked $toolbox @("doctor", "--config", "config\restricted.yml") }
    "serve" { Invoke-Checked $toolbox @("serve", "--config", "config\restricted.yml") }
    "test" { Invoke-Checked $python @("-m", "pytest") }
    "lint" {
        Invoke-Checked $python @("-m", "ruff", "format", "--check", ".")
        Invoke-Checked $python @("-m", "ruff", "check", ".")
    }
    "format" { Invoke-Checked $python @("-m", "ruff", "format", ".") }
    "typecheck" { Invoke-Checked $python @("-m", "mypy", "src") }
    "audit" {
        Invoke-Checked $python @("-m", "bandit", "-q", "-r", "src")
        Invoke-Checked $python @("-m", "pip_audit")
    }
    "docs-validate" {
        Invoke-Checked $python @("scripts\validate_docs.py")
        Invoke-Checked $python @("-m", "pytest", "tests\unit\test_demo_assets.py")
    }
    "package-build" { Invoke-Checked $python @("-m", "build") }
    "sbom" {
        New-Item -ItemType Directory -Force "dist" | Out-Null
        Invoke-Checked $python @("-m", "cyclonedx_py", "environment", "--output-file", "dist\sbom.cdx.json")
    }
    "compose-validate" {
        Invoke-Checked $docker @("compose", "--profile", "core", "-f", "compose.yaml", "config")
        Invoke-Checked $docker @("compose", "--profile", "docker", "-f", "compose.yaml", "config")
        Invoke-Checked $docker @("compose", "--profile", "development", "-f", "compose.yaml", "-f", "compose.dev.yaml", "config")
        Invoke-Checked $docker @("compose", "--profile", "direct-docker", "-f", "compose.yaml", "-f", "compose.direct-socket.yaml", "config")
    }
    "docker-build" { Invoke-Checked $docker @("build", "--tag", "local-mcp-toolbox:local", ".") }
    "docker-doctor" {
        Invoke-Checked $docker @("run", "--rm", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "local-mcp-toolbox:local", "doctor", "--config", "/app/config/container.yml")
    }
}
