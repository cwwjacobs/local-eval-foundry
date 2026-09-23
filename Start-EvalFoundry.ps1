param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$ModelEndpoint,

    [Parameter(Mandatory = $true)]
    [string]$Model,

    [ValidateSet('openai_compatible', 'lm_studio_chat')]
    [string]$ModelTransport = 'openai_compatible',

    [int]$Port = 8765,
    [string]$StateDir = (Join-Path $PSScriptRoot 'state'),
    [int]$MaxTokens = 220,
    [int]$TimeoutSeconds = 45,
    [double]$Temperature = 0.0,
    [string]$AllowOrigin
)

$bundledPython = 'C:\Users\ultra\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (Test-Path -LiteralPath $bundledPython) {
    $python = $bundledPython
} else {
    $python = (Get-Command python -ErrorAction Stop).Source
    $version = (& $python --version 2>&1 | Out-String).Trim()
    if ($version -notmatch '^Python 3\.(1[1-9]|[2-9][0-9])\.') {
        throw "EvalFoundry requires Python 3.11 or newer; found '$version'."
    }
}

$arguments = @(
    '-m', 'evalfoundry', 'serve',
    '--archive', $ArchivePath,
    '--model-endpoint', $ModelEndpoint,
    '--model', $Model,
    '--model-transport', $ModelTransport,
    '--state-dir', $StateDir,
    '--port', $Port,
    '--max-tokens', $MaxTokens,
    '--timeout-seconds', $TimeoutSeconds,
    '--temperature', $Temperature
)
if ($AllowOrigin) {
    $arguments += @('--allow-origin', $AllowOrigin)
}

Push-Location $PSScriptRoot
try {
    & $python @arguments
} finally {
    Pop-Location
}
