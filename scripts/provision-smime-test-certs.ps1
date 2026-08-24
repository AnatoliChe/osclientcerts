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

function New-RegressionCert {
    param(
        [string]$Subject,
        [string]$FriendlyName,
        [string]$KeyAlgorithm,
        [int]$KeyLength,
        [string]$KeySpec,
        [string[]]$KeyUsage
    )
    $existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.FriendlyName -eq $FriendlyName }
    if ($existing) {
        Write-Host "already present: $FriendlyName ($($existing.Thumbprint))"
        return
    }
    $params = @{
        Subject          = $Subject
        FriendlyName     = $FriendlyName
        KeyAlgorithm     = $KeyAlgorithm
        KeySpec          = $KeySpec
        KeyUsage         = $KeyUsage
        KeyExportPolicy  = 'NonExportable'
        NotAfter         = (Get-Date).AddYears(5)
        CertStoreLocation = 'Cert:\CurrentUser\My'
        # An RFC822/email SAN keeps the certificates realistic for S/MIME.
        TextExtension    = @("2.5.29.17={text}email=$FriendlyName@invalid")
    }
    if ($KeyLength -gt 0) {
        $params.KeyLength = $KeyLength
    }
    $cert = New-SelfSignedCertificate @params
    Write-Host "created: $FriendlyName ($($cert.Thumbprint))"
}

New-RegressionCert `
    -Subject 'CN=osclientcerts-smime-rsa' `
    -FriendlyName 'osclientcerts-smime-rsa' `
    -KeyAlgorithm 'RSA' `
    -KeyLength 2048 `
    -KeySpec 'KeyExchange' `
    -KeyUsage @('DigitalSignature', 'DataEncipherment', 'KeyEncipherment')

New-RegressionCert `
    -Subject 'CN=osclientcerts-smime-ec' `
    -FriendlyName 'osclientcerts-smime-ec' `
    -KeyAlgorithm 'ECDSA_nistP256' `
    -KeyLength 0 `
    -KeySpec 'Signature' `
    -KeyUsage @('DigitalSignature')

Write-Host 'regression test certificates ready'
