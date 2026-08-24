# Provision deterministic self-signed certificates used by the S/MIME regression tests
# (src/manager.rs, cfg(target_os = "windows")).
#
# Creates two non-exportable CNG keys in the current user's personal store:
#   - osclientcerts-smime-rsa : RSA-2048, KeyExchange (encrypt/decrypt + sign)
#   - osclientcerts-smime-ec  : ECDSA P-256, Signature (sign only)
#
# The certificates are marked with unique friendly names / subjects so the provider tests can find
# them deterministically even in a store that contains many other certificates. Existing test
# certificates are left alone, making the script idempotent for local re-runs.
#
# Usage (Windows, PowerShell):
#   powershell -ExecutionPolicy Bypass -File scripts\provision-smime-test-certs.ps1
#
# Cleanup:
#   Get-ChildItem Cert:\CurrentUser\My |
#     Where-Object { $_.FriendlyName -like 'osclientcerts-smime-*' } |
#     Remove-Item

$ErrorActionPreference = 'Stop'
Write-Host "provision: start (PS $($PSVersionTable.PSVersion))"

function New-RegressionCert {
    param(
        [string]$Subject,
        [string]$FriendlyName,
        [string]$KeyAlgorithm,
        [int]$KeyLength,
        [string]$KeySpec,
        [string[]]$KeyUsage
    )
    Write-Host "provision: checking for existing '$FriendlyName'..."
    $existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.FriendlyName -eq $FriendlyName }
    if ($existing) {
        Write-Host "provision: already present: $FriendlyName ($($existing.Thumbprint))"
        return
    }
    $params = @{
        Subject           = $Subject
        FriendlyName      = $FriendlyName
        KeyAlgorithm      = $KeyAlgorithm
        KeySpec           = $KeySpec
        KeyUsage          = $KeyUsage
        KeyExportPolicy   = 'NonExportable'
        NotAfter          = (Get-Date).AddYears(5)
        CertStoreLocation = 'Cert:\CurrentUser\My'
        # An RFC822/email SAN keeps the certificates realistic for S/MIME.
        TextExtension     = @("2.5.29.17={text}email=$FriendlyName@invalid")
    }
    if ($KeyLength -gt 0) {
        $params.KeyLength = $KeyLength
    }
    Write-Host "provision: creating '$FriendlyName' ($KeyAlgorithm)..."
    # Run in a job so a wedged KSP call fails loudly instead of hanging the CI job forever.
    $job = Start-Job -ScriptBlock { param($p) New-SelfSignedCertificate @p } -ArgumentList $params
    if (Wait-Job $job -Timeout 180) {
        $cert = Receive-Job $job
        Remove-Job $job
        Write-Host "provision: created '$FriendlyName' ($($cert.Thumbprint))"
    }
    else {
        Stop-Job $job
        Remove-Job $job -Force
        throw "New-SelfSignedCertificate timed out after 180s for '$FriendlyName'"
    }
}

$rsaParams = @{
    Subject     = 'CN=osclientcerts-smime-rsa'
    FriendlyName = 'osclientcerts-smime-rsa'
    KeyAlgorithm = 'RSA'
    KeyLength   = 2048
    KeySpec     = 'KeyExchange'
    KeyUsage    = @('DigitalSignature', 'DataEncipherment', 'KeyEncipherment')
}
New-RegressionCert @rsaParams

$ecParams = @{
    Subject      = 'CN=osclientcerts-smime-ec'
    FriendlyName = 'osclientcerts-smime-ec'
    KeyAlgorithm = 'ECDSA_nistP256'
    KeyLength    = 0
    KeySpec      = 'Signature'
    KeyUsage     = @('DigitalSignature')
}
New-RegressionCert @ecParams

Write-Host 'provision: regression test certificates ready'
