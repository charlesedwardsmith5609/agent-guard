# Cross-model review: send the current diff to a different AI provider for an independent review.
# Usage: pwsh -NoProfile -File scripts/cross-review.ps1 [-Provider openai|anthropic] [-Model NAME] [-Base REF]
# Env:   OPENAI_API_KEY / ANTHROPIC_API_KEY, optional REVIEW_PROVIDER, REVIEW_MODEL,
#        OPENAI_BASE_URL, ANTHROPIC_BASE_URL
param(
    [ValidateSet('openai', 'anthropic')]
    [string]$Provider = $(if ($env:REVIEW_PROVIDER) { $env:REVIEW_PROVIDER } else { 'openai' }),
    [string]$Model = $env:REVIEW_MODEL,
    [string]$Base = 'HEAD'
)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if ($Provider -eq 'openai') {
    if (-not $Model) { $Model = 'gpt-6.1-sol' }
    $key = $env:OPENAI_API_KEY
    $root = if ($env:OPENAI_BASE_URL) { $env:OPENAI_BASE_URL } else { 'https://api.openai.com' }
    $url = "$root/v1/chat/completions"
} else {
    if (-not $Model) { $Model = 'claude-sonnet-5-5' }
    $key = $env:ANTHROPIC_API_KEY
    $root = if ($env:ANTHROPIC_BASE_URL) { $env:ANTHROPIC_BASE_URL } else { 'https://api.anthropic.com' }
    $url = "$root/v1/messages"
}
if (-not $key) { Write-Error "Missing API key for $Provider"; exit 2 }

# Include new, untracked files in the diff without staging their content.
& git add --intent-to-add --all 2>$null | Out-Null
function Get-ReviewDiff([string]$Ref) {
    (& git diff --no-color $Ref -- . ':(exclude)go.sum' ':(exclude)**/go.sum' ':(exclude)**/package-lock.json' | Out-String)
}
$diff = Get-ReviewDiff $Base
# Nothing uncommitted and no -Base given: review the last commit instead.
if (-not $diff.Trim() -and -not $PSBoundParameters.ContainsKey('Base')) {
    & git rev-parse -q --verify HEAD~1 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $Base = 'HEAD~1'
        Write-Host "No uncommitted changes; reviewing the last commit: $(& git log -1 --format='%h %s')" -ForegroundColor Cyan
        Write-Host "(If the milestone spans several commits, rerun with -Base REF.)" -ForegroundColor DarkGray
        $diff = Get-ReviewDiff $Base
    }
}
if (-not $diff.Trim()) { Write-Host "No changes against $Base. Nothing to review."; exit 0 }
$max = 60000
if ($diff.Length -gt $max) {
    Write-Warning "Diff is $($diff.Length) chars; truncating to $max."
    $diff = $diff.Substring(0, $max)
}

$system = Get-Content -Raw -Encoding UTF8 'skills/review-checklist.md'
$user = "Review this diff:`n`n``````diff`n$diff`n``````"

# Secret scan before anything leaves this machine. A finding refuses the review. If gitleaks is
# not installed this only warns and the review goes ahead unscanned.
if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Warning "gitleaks is not installed; sending this review to $Provider WITHOUT a secret scan."
} else {
    $ErrorActionPreference = 'Continue'   # native stderr must not throw while we capture it
    # `gitleaks stdin` is the current form; older 8.x releases only have `detect --pipe`.
    $useStdin = (& gitleaks stdin --help 2>&1 | Out-String) -match 'gitleaks stdin'
    $gl = if ($useStdin) { @('stdin') } else { @('detect', '--pipe') }
    $scan = $user | & gitleaks @gl --no-banner --no-color --redact --verbose --exit-code 7 2>&1 | Out-String
    $scanExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($scanExit -ne 0) {
        Write-Host (($scan -split "`r?`n" | Select-Object -Last 25) -join "`n")
        if ($scanExit -eq 7) {
            Write-Error "Secret scan found possible secrets (redacted above). Nothing was sent. Remove them from the change and rerun."
        } else {
            Write-Error "Secret scan failed (gitleaks exit $scanExit). Nothing was sent."
        }
        exit 1
    }
}

if ($Provider -eq 'openai') {
    $req = @{ model = $Model; messages = @(@{ role = 'system'; content = $system }, @{ role = 'user'; content = $user }) }
    $headers = @{ Authorization = "Bearer $key" }
} else {
    $req = @{ model = $Model; max_tokens = 2000; system = $system; messages = @(@{ role = 'user'; content = $user }) }
    $headers = @{ 'x-api-key' = $key; 'anthropic-version' = '2023-06-01' }
}
$json = $req | ConvertTo-Json -Depth 6
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

Write-Host "Requesting review from $Provider ($Model)..." -ForegroundColor Cyan
try {
    $resp = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bytes
} catch {
    Write-Error "API call failed: $($_.Exception.Message) $($_.ErrorDetails.Message)"
    exit 1
}

if ($Provider -eq 'openai') {
    $review = $resp.choices[0].message.content
} else {
    $review = ($resp.content | Where-Object { $_.type -eq 'text' } | ForEach-Object { $_.text }) -join ''
}

New-Item -ItemType Directory -Force -Path '.reviews' | Out-Null
$out = ".reviews/review-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$Provider.md"
"# Cross-model review ($Provider, $Model, base $Base)`n`n$review" | Set-Content -Encoding UTF8 $out
Write-Host $review
Write-Host "`nSaved to $out" -ForegroundColor DarkGray
