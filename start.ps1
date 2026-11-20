# HookProof interactive launcher.
# Dot-source from your PowerShell profile:  . "<path>\HookProof\start.ps1"
# Skip the boot animation with:            hp -NoAnimation

param([switch]$NoAnimation)

$root = $PSScriptRoot
Set-Location $root

$inner = 57

function Write-BorderStart {
    Write-Host ('  +' + ('-' * $inner) + '+') -ForegroundColor Cyan
}

function Write-BorderEnd {
    Write-Host ('  +' + ('-' * $inner) + '+') -ForegroundColor Cyan
}

function Write-Row {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    $padding = [Math]::Max(0, $inner - $Text.Length)
    Write-Host '  |' -NoNewline -ForegroundColor Cyan
    Write-Host ($Text + (' ' * $padding)) -NoNewline -ForegroundColor $Color
    Write-Host '|' -ForegroundColor Cyan
}

Write-Host ''
Write-BorderStart
Write-Row ''
Write-Row '    H O O K P R O O F' ([ConsoleColor]::Cyan)
Write-Row '    EffectProof - webhook security testing' ([ConsoleColor]::Gray)
Write-Row ''
Write-BorderEnd

if (-not (Test-Path (Join-Path $root '.venv\Scripts\Activate.ps1'))) {
    Write-Host ''
    Write-Host '  [X] .venv not found in this project.' -ForegroundColor Red
    Write-Host '      Run these once:' -ForegroundColor Yellow
    Write-Host '        python -m venv .venv' -ForegroundColor Gray
    Write-Host '        .\.venv\Scripts\Activate.ps1' -ForegroundColor Gray
    Write-Host '        pip install -e ".[dev]"' -ForegroundColor Gray
    Write-Host ''
    return
}

if ($NoAnimation) {
    Write-Host '  [*] activating environment' -ForegroundColor DarkCyan
} else {
    $frames = @('|', '/', '-', '\')
    $label = '  [*] activating environment '
    foreach ($i in 0..11) {
        Write-Host ("`r" + $label + $frames[$i % 4]) -NoNewline -ForegroundColor DarkCyan
        Start-Sleep -Milliseconds 55
    }
    Write-Host ("`r" + $label) -NoNewline -ForegroundColor DarkCyan
    Write-Host '  [OK]' -ForegroundColor Green
}

. (Join-Path $root '.venv\Scripts\Activate.ps1')

$pyVersion = (& python --version 2>&1)
Write-Host "  [OK] environment ready  " -NoNewline -ForegroundColor Green
Write-Host "($pyVersion)" -ForegroundColor DarkGray
Write-Host ''

Write-Host '  quick start' -ForegroundColor Cyan
Write-Host '    hookproof lab serve --mode vulnerable' -ForegroundColor White
Write-Host '        start the intentionally broken lab (127.0.0.1:8000)' -ForegroundColor DarkGray
Write-Host '    hookproof lab serve --mode secure' -ForegroundColor White
Write-Host '        start the hardened lab' -ForegroundColor DarkGray
Write-Host '    hookproof scan --target http://127.0.0.1:8000/webhooks/payment --suite core' -ForegroundColor White
Write-Host '        run EffectProof against the running lab' -ForegroundColor DarkGray
Write-Host '    pytest' -ForegroundColor White
Write-Host '        run the automated test suite' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  tip: hp -NoAnimation skips this screen' -ForegroundColor DarkGray
Write-Host ''
