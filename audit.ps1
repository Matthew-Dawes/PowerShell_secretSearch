# =============================================================================
# audit.ps1 - Security pattern scanner
# Usage:
#   .\audit.ps1                                         # Run all categories
#   .\audit.ps1 -Categories SSL, Secrets                # Run specific categories
#   .\audit.ps1 -Categories Secrets -Path "C:\Project"  # Target a folder
#   .\audit.ps1 -ExportCsv                              # Save results to CSV
#   .\audit.ps1 -ListCategories                         # Show available categories
# =============================================================================

param(
    [string[]]$Categories = @(),        # Empty = all categories
    [string]$Path = ".",
    [switch]$ExportCsv,
    [switch]$ListCategories
)

# =============================================================================
# PATTERN GROUPS
# =============================================================================

$patternGroups = @{

    SSL = @{
        Description = "SSL/TLS verification disabled"
        Patterns = @(
            # Python
            "verify=False",
            "verify=false",
            "ssl_verify\s*=\s*[Ff]alse",
            "check_hostname\s*=\s*False",
            "CERT_NONE",
            "InsecureRequestWarning",
            "urllib3\.disable_warnings",
            # Node / JS
            "rejectUnauthorized:\s*false",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "strictSSL:\s*false",
            # Java
            "TrustAllCerts",
            "X509TrustManager",
            "setHostnameVerifier",
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            # General
            "DISABLE_SSL",
            "skipVerify\s*=\s*true",
            "tls_verify\s*=\s*false",
            "sslVerify\s*=\s*false",
            "ignore_ssl"
        )
    }

    Secrets = @{
        Description = "Hardcoded secrets and credentials"
        Patterns = @(
            # Generic key/value literals
            "password\s*=\s*[`"'][^`"']{4,}",
            "passwd\s*=\s*[`"'][^`"']{4,}",
            "secret\s*=\s*[`"'][^`"']{4,}",
            "api_key\s*=\s*[`"'][^`"']{4,}",
            "apikey\s*=\s*[`"'][^`"']{4,}",
            "auth_token\s*=\s*[`"'][^`"']{4,}",
            "access_token\s*=\s*[`"'][^`"']{4,}",
            "private_key\s*=\s*[`"'][^`"']{4,}",
            # AWS
            "AKIA[0-9A-Z]{16}",
            "aws_secret_access_key",
            # Google
            "AIza[0-9A-Za-z\-_]{35}",
            # Azure
            "AccountKey=",
            "DefaultEndpointsProtocol=",
            # Tokens
            "ghp_[a-zA-Z0-9]{36}",
            "xox[baprs]-[0-9a-zA-Z]{10,}",
            "Bearer [a-zA-Z0-9\-_]{20,}",
            "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
            # DB connection strings
            "mongodb(\+srv)?://[^`"'\s]{8,}",
            "postgres://[^`"'\s]{8,}",
            "mysql://[^`"'\s]{8,}",
            "Server=.*;Database=.*;User"
        )
    }

    WeakCrypto = @{
        Description = "Weak or deprecated cryptographic functions"
        Patterns = @(
            "MD5",
            "SHA1\(",
            "SHA-1",
            "DES\.",
            "3DES",
            "RC4",
            "ECB",              # Weak AES block mode
            "RSA_PKCS1_PADDING" # Vulnerable RSA padding
        )
    }

    Debug = @{
        Description = "Debug/dev flags that should not be in production"
        Patterns = @(
            "DEBUG\s*=\s*True",
            "DEBUG\s*=\s*true",
            "ENV\s*=\s*[`"']dev",
            "FLASK_DEBUG",
            "DJANGO_DEBUG",
            "NODE_ENV\s*=\s*[`"']development",
            "APP_ENV\s*=\s*[`"']dev",
            "enableDebug\s*=\s*true",
            "verbose\s*=\s*true"
        )
    }

    DangerousFunctions = @{
        Description = "Dangerous or unsafe function calls"
        Patterns = @(
            "eval\(",
            "exec\(",
            "pickle\.loads",        # Python deserialization
            "yaml\.load\(",         # Unsafe YAML load (use safe_load)
            "deserialize\(",
            "unserialize\(",        # PHP deserialization
            "Runtime\.exec\(",      # Java shell exec
            "child_process\.exec",  # Node shell exec
            "subprocess\.call.*shell=True", # Python shell injection risk
            "os\.system\("
        )
    }

}

# =============================================================================
# FILE EXTENSIONS TO SCAN
# =============================================================================

$fileExtensions = @(
    "*.py", "*.js", "*.ts", "*.jsx", "*.tsx",
    "*.json", "*.yaml", "*.yml",
    "*.env", "*.env.*",
    "*.cfg", "*.ini", "*.toml", "*.conf",
    "*.java", "*.cs", "*.go", "*.rb", "*.php",
    "*.xml", "*.properties"
)

# =============================================================================
# HELPERS
# =============================================================================

function Write-Header {
    param([string]$Text, [string]$Color = "Cyan")
    Write-Host "`n$("=" * 60)" -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host "$("=" * 60)" -ForegroundColor $Color
}

function Get-IsTestFile {
    param([string]$FilePath)
    return $FilePath -match "(\\|/)(tests?|__tests__|spec|mocks?|fixtures?)(\\|/)" `
        -or $FilePath -match "\.(test|spec)\.(js|ts|py|cs)$"
}

# =============================================================================
# LIST CATEGORIES MODE
# =============================================================================

if ($ListCategories) {
    Write-Header "Available Categories"
    foreach ($key in $patternGroups.Keys | Sort-Object) {
        Write-Host "  $key" -ForegroundColor Yellow -NoNewline
        Write-Host " - $($patternGroups[$key].Description)"
    }
    Write-Host ""
    exit
}

# =============================================================================
# RESOLVE WHICH CATEGORIES TO RUN
# =============================================================================

$activeCategories = if ($Categories.Count -gt 0) {
    $Categories
} else {
    $patternGroups.Keys | Sort-Object
}

# Validate category names
foreach ($cat in $activeCategories) {
    if (-not $patternGroups.ContainsKey($cat)) {
        Write-Host "Unknown category: '$cat'. Run with -ListCategories to see options." -ForegroundColor Red
        exit 1
    }
}

# =============================================================================
# SCAN
# =============================================================================

Write-Header "Security Audit - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Host "  Path       : $((Resolve-Path $Path).Path)"
Write-Host "  Categories : $($activeCategories -join ', ')"

$allResults = @()

foreach ($category in $activeCategories) {
    $group = $patternGroups[$category]
    Write-Host "`nScanning: $category - $($group.Description)..." -ForegroundColor DarkCyan

    foreach ($pattern in $group.Patterns) {
        $matches = Get-ChildItem -Path $Path -Recurse -File -Include $fileExtensions -ErrorAction SilentlyContinue |
            Select-String -Pattern $pattern -ErrorAction SilentlyContinue

        foreach ($match in $matches) {
            $isTest = Get-IsTestFile -FilePath $match.Path
            $allResults += [PSCustomObject]@{
                Category  = $category
                Pattern   = $pattern
                File      = $match.Path
                Line      = $match.LineNumber
                Content   = $match.Line.Trim()
                IsTestFile = $isTest
            }
        }
    }
}

# =============================================================================
# OUTPUT
# =============================================================================

if ($allResults.Count -eq 0) {
    Write-Host "`nNo matches found." -ForegroundColor Green
    exit
}

# Split into prod and test findings
$prodResults = $allResults | Where-Object { -not $_.IsTestFile }
$testResults = $allResults | Where-Object { $_.IsTestFile }

# --- Main findings ---
Write-Header "Findings: $($prodResults.Count) match(es) in production code" "Yellow"
if ($prodResults.Count -gt 0) {
    $prodResults | Format-Table Category, File, Line, Content -Wrap
}

# --- Test file findings (lower priority) ---
if ($testResults.Count -gt 0) {
    Write-Header "Test File Findings: $($testResults.Count) match(es) - lower priority" "DarkYellow"
    $testResults | Format-Table Category, File, Line, Content -Wrap
}

# --- Files to review ---
Write-Header "Files to Review ($($prodResults | Select-Object -ExpandProperty File -Unique | Measure-Object | Select-Object -ExpandProperty Count) unique)" "Cyan"
$prodResults | Select-Object -ExpandProperty File -Unique | ForEach-Object {
    $cats = ($prodResults | Where-Object { $_.File -eq $_ } | Select-Object -ExpandProperty Category -Unique) -join ", "
    Write-Host "  -> $_ " -NoNewline
    Write-Host "[$cats]" -ForegroundColor DarkGray
}

# --- Summary by category ---
Write-Header "Summary by Category" "Cyan"
$allResults | Group-Object Category | ForEach-Object {
    $prodCount = ($_.Group | Where-Object { -not $_.IsTestFile }).Count
    $testCount = ($_.Group | Where-Object { $_.IsTestFile }).Count
    Write-Host ("  {0,-20} {1,3} prod match(es)   {2,3} test match(es)" -f $_.Name, $prodCount, $testCount)
}

# =============================================================================
# OPTIONAL CSV EXPORT
# =============================================================================

if ($ExportCsv) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = "audit_results_$timestamp.csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nResults exported to: $csvPath" -ForegroundColor Green
}

Write-Host ""
