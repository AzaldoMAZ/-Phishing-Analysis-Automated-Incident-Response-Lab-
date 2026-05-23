# Organize portfolio screenshots into STEP BY STEP and category folders
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

$ss = Join-Path $root "screenshots"
$steps = Join-Path $ss "STEP BY STEP"
$media = Join-Path $root "media"

New-Item -ItemType Directory -Force -Path $steps, $media,
    (Join-Path $ss "TERMINAL RESULTS"),
    (Join-Path $ss "quishing"),
    (Join-Path $ss "artifacts"),
    (Join-Path $ss "_archive") | Out-Null

function Copy-Step($src, $destName, $caption) {
    if (-not (Test-Path $src)) { Write-Warning "Missing: $src"; return }
    $dest = Join-Path $steps $destName
    Copy-Item -Path $src -Destination $dest -Force
    Add-Content (Join-Path $steps "_captions.txt") "$destName | $caption"
}

# Curated build order (source path relative to screenshots/)
$map = @(
    @("UBUNTU INSTALL\Screenshot 2026-05-11 214902.png", "01-virtualbox-lab-setup.png", "VirtualBox lab environment"),
    @("UBUNTU INSTALL\Screenshot 2026-05-13 225639.png", "02-environment-splunk-host.png", "Splunk / lab host ready"),
    @("PHISHING EMAIL\Screenshot 2026-05-13 211552.png", "03-phishing-eml-sample.png", "Phishing .eml sample"),
    @("PHISHING EMAIL\Screenshot 2026-05-13 212808.png", "04-email-header-analysis.png", "SPF / DKIM / DMARC header analysis"),
    @("PHISHING EMAIL\Screenshot 2026-05-13 213812.png", "05-ioc-extraction-spreadsheet.png", "IOC extraction spreadsheet"),
    @("SPLUNK\Screenshot 2026-05-15 205820.png", "06-splunk-ingest-mailserver01.png", "Splunk data ingest host mailserver01"),
    @("SPLUNK\Screenshot 2026-05-15 205840.png", "07-splunk-phishing-log-search.png", "Search phishing_mail.log in Splunk"),
    @("SPLUNK\Screenshot 2026-05-15 210346.png", "08-splunk-spl-detection-table.png", "SPL detection IOC table"),
    @("SPLUNK\Screenshot 2026-05-15 210402.png", "09-splunk-save-as-alert.png", "Save detection as scheduled alert"),
    @("SPLUNK\Screenshot 2026-05-15 210428.png", "10-splunk-alert-email-action.png", "Alert trigger email action"),
    @("SPLUNK\Screenshot 2026-05-15 210920.png", "11-splunk-stats-by-recipient.png", "Stats count by recipient"),
    @("SPLUNK\Screenshot 2026-05-15 211039.png", "12-splunk-stats-by-src-ip.png", "Stats count by src_ip"),
    @("SPLUNK\Screenshot 2026-05-15 211854.png", "13-splunk-repeat-phishing-alert.png", "Alert PHI-2026-001 repeat source"),
    @("IOC ENRICHMENT PYTHON\Screenshot 2026-05-13 220717.png", "14-python-ioc-enrichment-code.png", "ioc_enrichment.py script"),
    @("IOC ENRICHMENT PYTHON\Screenshot 2026-05-13 221100.png", "15-terminal-enrichment-run.png", "Terminal enrichment engine running"),
    @("IOC ENRICHMENT PYTHON\Screenshot 2026-05-13 223357.png", "16-ioc-enrichment-summary.png", "IOC summary output"),
    @("SHUFFLE WORKFLOW\Screenshot 2026-05-18 072609.png", "17-shuffle-soar-overview.png", "Shuffle SOAR workflow overview"),
    @("SHUFFLE WORKFLOW\Screenshot 2026-05-20 212619.png", "18-shuffle-workflow-build.png", "Shuffle workflow nodes"),
    @("SHUFFLE WORKFLOW\Screenshot 2026-05-20 213454.png", "19-shuffle-webhook-execution.png", "Shuffle webhook execution success")
)

Remove-Item (Join-Path $steps "_captions.txt") -ErrorAction SilentlyContinue
foreach ($m in $map) {
    Copy-Step (Join-Path $ss $m[0]) $m[1] $m[2]
}

# Terminal results (subset)
$term = Join-Path $ss "TERMINAL RESULTS"
@(
    "IOC ENRICHMENT PYTHON\Screenshot 2026-05-13 221057.png",
    "IOC ENRICHMENT PYTHON\Screenshot 2026-05-13 221048.png",
    "IOC ENRICHMENT PYTHON\Screenshot 2026-05-13 220938.png"
) | ForEach-Object {
    $name = Split-Path $_ -Leaf
    Copy-Item (Join-Path $ss $_) (Join-Path $term $name) -Force -ErrorAction SilentlyContinue
}

# Quishing artifact
$qr = Join-Path $root "samples\quishing_lure.png"
if (Test-Path $qr) {
    Copy-Item $qr (Join-Path $ss "quishing\quishing_lure.png") -Force
    Copy-Item $qr (Join-Path $steps "20-quishing-qr-lure.png") -Force
}

# Move misplaced code out of screenshots/dashboard
$dashCode = Join-Path $ss "dashboard"
if (Test-Path (Join-Path $dashCode "app.py")) {
    $arch = Join-Path $ss "_archive\dashboard-code-snapshots"
    New-Item -ItemType Directory -Force -Path $arch | Out-Null
    Move-Item "$dashCode\*" $arch -Force -ErrorAction SilentlyContinue
}

# Media: copy Desktop lab video if present
$desktopVideo = Join-Path (Split-Path $root -Parent) "Phishing-IR-Lab VIDEO.mp4"
if (Test-Path $desktopVideo) {
    Copy-Item $desktopVideo (Join-Path $media "phishing-ir-lab-demo.mp4") -Force
    Write-Host "Copied lab video to media/phishing-ir-lab-demo.mp4"
}

# Media: move any video found in screenshots subfolders to media/
Get-ChildItem $ss -Recurse -Include *.mp4,*.webm,*.mov,*.mkv -File -ErrorAction SilentlyContinue | ForEach-Object {
    $dest = Join-Path $media "phishing-ir-lab-demo$($_.Extension)"
    Move-Item $_.FullName $dest -Force
    Write-Host "Moved video to $dest"
}

Write-Host "Done. STEP BY STEP: $((Get-ChildItem $steps -Filter *.png).Count) images"
