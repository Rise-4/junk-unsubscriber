# ============================================================
# verify-defender-headers.ps1
# ============================================================
# Vérifie que Defender (BCL/CAT) est bien posé sur les emails de ta boîte M365.
# Utilise internetMessageHeaders (chemin qu'utilise la 2e passe de l'app) pour
# voir TOUS les headers — y compris les X-Microsoft-* qui ne sont pas indexés
# dans PSETID_InternetHeaders.
#
# Scanne Inbox ET Indésirables pour avoir un échantillon représentatif.
#
# Usage : .\verify-defender-headers.ps1
# Auth  : device code (URL + code à coller dans le navigateur)
# Scope : Mail.Read (lecture seule)
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== Vérification headers Defender (Junk Unsubscriber) ===" -ForegroundColor Cyan
Write-Host ""

# --- Auth device code ---
$clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
$deviceResp = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" `
    -Body @{ client_id = $clientId; scope = "https://graph.microsoft.com/Mail.Read offline_access" }

Write-Host "1. Ouvre dans ton navigateur : " -NoNewline; Write-Host $deviceResp.verification_uri -ForegroundColor Cyan
Write-Host "2. Colle ce code             : " -NoNewline; Write-Host $deviceResp.user_code -ForegroundColor Cyan
Write-Host "3. Connecte-toi avec tlegal@rise.fo"
Write-Host ""
Write-Host "En attente..." -NoNewline

$token = $null
$deadline = (Get-Date).AddSeconds([int]$deviceResp.expires_in)
$interval = [int]$deviceResp.interval
while (-not $token -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $interval
    Write-Host "." -NoNewline
    try {
        $tokResp = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
            -Body @{ grant_type = "urn:ietf:params:oauth:grant-type:device_code"; client_id = $clientId; device_code = $deviceResp.device_code } -ErrorAction Stop
        $token = $tokResp.access_token
    } catch {
        $errBody = $null; try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
        if ($errBody -and $errBody.error -eq "authorization_pending") { continue }
        if ($errBody -and $errBody.error -eq "slow_down")             { $interval += 5; continue }
        if ($errBody) { Write-Host ""; throw "Auth : $($errBody.error) — $($errBody.error_description)" }
        throw
    }
}
Write-Host ""
if (-not $token) { throw "Timeout" }
Write-Host "OK : authentifié" -ForegroundColor Green

$authHdrs = @{ Authorization = "Bearer $token" }

# --- Récupération messages avec ALL headers (Inbox + Junk) ---
function Get-MessagesWithHeaders($folder, $top = 100) {
    $url = "https://graph.microsoft.com/v1.0/me/mailFolders/$folder/messages?`$top=$top&`$select=id,subject,from,internetMessageHeaders"
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $authHdrs
        return @($resp.value)
    } catch {
        Write-Host "  (impossible de scanner $folder : $($_.Exception.Message))" -ForegroundColor Yellow
        return @()
    }
}

Write-Host ""
Write-Host "Récupération Inbox (jusqu'à 100 emails)..."
$inboxMsgs = Get-MessagesWithHeaders "inbox" 100
Write-Host "  $($inboxMsgs.Count) emails"

Write-Host "Récupération Indésirables (jusqu'à 100 emails)..."
$junkMsgs = Get-MessagesWithHeaders "junkemail" 100
Write-Host "  $($junkMsgs.Count) emails"

$allMsgs = @($inboxMsgs) + @($junkMsgs)
if ($allMsgs.Count -eq 0) {
    Write-Host "Boîte vide." -ForegroundColor Red; return
}

# --- Analyse ---
$stats = @{
    Total           = $allMsgs.Count
    HasAntispam     = 0; HasForefront = 0
    HasListUnsubscribe = 0; HasListId = 0; HasFeedbackId = 0
    HasPrecedence   = 0; HasAutoSubmitted = 0
}
$bclDist = [ordered]@{ "0" = 0; "1-3" = 0; "4-7" = 0; "8-9" = 0 }
$catDist = @{}
$bulkReasons = @{}
$sample = New-Object System.Collections.ArrayList

function HeaderValue($hdrs, $name) {
    if (-not $hdrs) { return $null }
    $h = $hdrs | Where-Object { $_.name -ieq $name } | Select-Object -First 1
    if ($h) { return $h.value }
    return $null
}

foreach ($m in $allMsgs) {
    $hdrs = $m.internetMessageHeaders
    $folder = if ($inboxMsgs -contains $m) { "Inbox" } else { "Junk" }

    $antispam = HeaderValue $hdrs "X-Microsoft-Antispam"
    $bcl = $null
    if ($antispam) {
        $stats.HasAntispam++
        if ($antispam -match 'BCL:(\d+)') {
            $bcl = [int]$Matches[1]
            if     ($bcl -eq 0) { $bclDist["0"]++ }
            elseif ($bcl -le 3) { $bclDist["1-3"]++ }
            elseif ($bcl -le 7) { $bclDist["4-7"]++ }
            else                { $bclDist["8-9"]++ }
        }
    }

    $forefront = HeaderValue $hdrs "X-Forefront-Antispam-Report"
    $cat = $null
    if ($forefront) {
        $stats.HasForefront++
        if ($forefront -match 'CAT:([A-Z]+)') {
            $cat = $Matches[1]
            if (-not $catDist.ContainsKey($cat)) { $catDist[$cat] = 0 }
            $catDist[$cat]++
        }
    }

    if (HeaderValue $hdrs "List-Unsubscribe") { $stats.HasListUnsubscribe++ }
    if (HeaderValue $hdrs "List-ID")          { $stats.HasListId++ }
    if (HeaderValue $hdrs "Feedback-ID")      { $stats.HasFeedbackId++ }
    $prec = HeaderValue $hdrs "Precedence"
    if ($prec)        { $stats.HasPrecedence++ }
    $autoSub = HeaderValue $hdrs "Auto-Submitted"
    if ($autoSub)     { $stats.HasAutoSubmitted++ }

    # Logique extractBulkSignals
    $reason = $null
    if     ($null -ne $bcl -and $bcl -ge 1)               { $reason = "BCL>=1" }
    elseif ($cat -in @("BULK", "SPM", "HSPM"))            { $reason = "CAT:$cat" }
    elseif (HeaderValue $hdrs "List-ID")                  { $reason = "List-ID" }
    elseif (HeaderValue $hdrs "Feedback-ID")              { $reason = "Feedback-ID" }
    elseif ($prec -and $prec -match '^(bulk|list|junk)\b')     { $reason = "Precedence" }
    elseif ($autoSub -and $autoSub -match '^(auto-generated|auto-replied)\b') { $reason = "Auto-Submitted" }
    elseif (HeaderValue $hdrs "List-Unsubscribe")         { $reason = "List-Unsubscribe" }

    if ($reason) {
        if (-not $bulkReasons.ContainsKey($reason)) { $bulkReasons[$reason] = 0 }
        $bulkReasons[$reason]++
    }

    if ($sample.Count -lt 15) {
        $subj = if ($m.subject) {
            if ($m.subject.Length -gt 40) { $m.subject.Substring(0, 40) + "…" } else { $m.subject }
        } else { "(sans objet)" }
        $from = if ($m.from -and $m.from.emailAddress) { $m.from.emailAddress.address } else { "?" }
        [void]$sample.Add([PSCustomObject]@{
            Folder  = $folder
            BCL     = if ($null -ne $bcl) { $bcl } else { "?" }
            CAT     = if ($cat) { $cat } else { "-" }
            Bulk    = if ($reason) { "OUI ($reason)" } else { "non" }
            From    = $from
            Subject = $subj
        })
    }
}

# --- Rapport ---
$tot = $stats.Total
function Pct([int]$n, [int]$t) { if ($t -eq 0) { "  0%" } else { "{0,3}%" -f [int](($n / $t) * 100) } }

Write-Host ""
Write-Host "=== Couverture des headers (Inbox $($inboxMsgs.Count) + Junk $($junkMsgs.Count) = $tot emails) ===" -ForegroundColor Cyan
Write-Host ("X-Microsoft-Antispam (BCL)       : {0,4} / {1} ({2})  <- signal primaire" -f $stats.HasAntispam, $tot, (Pct $stats.HasAntispam $tot))
Write-Host ("X-Forefront-Antispam-Report      : {0,4} / {1} ({2})" -f $stats.HasForefront, $tot, (Pct $stats.HasForefront $tot))
Write-Host ("List-Unsubscribe (action)        : {0,4} / {1} ({2})" -f $stats.HasListUnsubscribe, $tot, (Pct $stats.HasListUnsubscribe $tot))
Write-Host ("List-ID (fallback)               : {0,4} / {1} ({2})" -f $stats.HasListId, $tot, (Pct $stats.HasListId $tot))
Write-Host ("Feedback-ID (fallback)           : {0,4} / {1} ({2})" -f $stats.HasFeedbackId, $tot, (Pct $stats.HasFeedbackId $tot))
Write-Host ("Precedence (fallback)            : {0,4} / {1} ({2})" -f $stats.HasPrecedence, $tot, (Pct $stats.HasPrecedence $tot))
Write-Host ("Auto-Submitted (fallback)        : {0,4} / {1} ({2})" -f $stats.HasAutoSubmitted, $tot, (Pct $stats.HasAutoSubmitted $tot))

Write-Host ""
Write-Host "=== Distribution BCL (emails où le header est présent) ===" -ForegroundColor Cyan
Write-Host ("BCL=0   humain/transactionnel    : {0,4}" -f $bclDist["0"])
Write-Host ("BCL=1-3 bulk propre              : {0,4}" -f $bclDist["1-3"])
Write-Host ("BCL=4-7 bulk mitigé              : {0,4}" -f $bclDist["4-7"])
Write-Host ("BCL=8-9 bulk spammy              : {0,4}" -f $bclDist["8-9"])

if ($catDist.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Distribution CAT (Defender) ===" -ForegroundColor Cyan
    foreach ($k in ($catDist.Keys | Sort-Object { -$catDist[$_] })) {
        Write-Host ("{0,-8} : {1,4}" -f $k, $catDist[$k])
    }
}

$totalBulk = 0
$bulkReasons.Values | ForEach-Object { $totalBulk += $_ }
Write-Host ""
Write-Host "=== Ce que le nouveau Junk Unsubscriber détecterait ===" -ForegroundColor Cyan
Write-Host ("Emails classés bulk : $totalBulk / $tot ({0})" -f (Pct $totalBulk $tot))
foreach ($k in ($bulkReasons.Keys | Sort-Object { -$bulkReasons[$_] })) {
    Write-Host ("  via {0,-22} : {1}" -f $k, $bulkReasons[$k])
}

Write-Host ""
Write-Host "=== Échantillon (15 emails) ===" -ForegroundColor Cyan
$sample | Format-Table -AutoSize

# --- Verdict ---
Write-Host ""
Write-Host "=== VERDICT ===" -ForegroundColor Cyan
$coverage = if ($tot -gt 0) { $stats.HasAntispam / $tot } else { 0 }
$pctCov = [int]($coverage * 100)
if ($coverage -ge 0.8) {
    Write-Host "OK : Defender pose ses headers sur $pctCov% des emails." -ForegroundColor Green
    Write-Host "     Le nouveau Junk Unsubscriber fonctionnera pleinement." -ForegroundColor Green
} elseif ($coverage -ge 0.2) {
    Write-Host "WARN : Defender absent sur une partie des emails ($pctCov%)." -ForegroundColor Yellow
    Write-Host "       Gateway tiers qui strip parfois les X-Microsoft-*. Les fallbacks RFC prendront le relai." -ForegroundColor Yellow
} else {
    Write-Host "KO : Defender quasi absent ($pctCov%)." -ForegroundColor Red
    Write-Host "     Ta boîte est derrière un gateway tiers (Proofpoint/Mimecast/etc.)." -ForegroundColor Red
    Write-Host "     La détection retombera sur List-ID/Feedback-ID/Precedence — couverture ~50-70%." -ForegroundColor Red
}
Write-Host ""
