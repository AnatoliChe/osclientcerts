# Provision deterministic self-signed certificates used by the S/MIME regression tests
# (src/manager.rs, cfg(target_os = "windows")).
#
# Creates two non-exportable keys in the current user's personal store via the default CNG
# provider (Microsoft Software Key Storage Provider), so every private key is an NCrypt key:
#   - osclientcerts-smime-rsa : RSA-2048 with KeySpec KeyExchange (decrypt + sign via PKCS#11)
#   - osclientcerts-smime-ec  : ECDSA P-256, signing only
#
# The two certificate families are deliberately created through separate parameter sets: KeySpec is
# a legacy CryptoAPI concept that maps CNG key usage bits for provider-backed keys. RSA keeps
# 'KeyExchange'; pure CNG algorithms such as ECDSA_nistP256 must never carry a KeySpec - passing
# one fails with NTE_PROV_TYPE_NOT_DEF.
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

function New-CngKeyCert {
    param(
        [string]$Subject,
        [string]$FriendlyName,
        # Algorithm-specific parameters, already resolved per key family by the callers below.
        [hashtable]$KeyParameters
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
        KeyExportPolicy   = 'NonExportable'
        NotAfter          = (Get-Date).AddYears(5)
        CertStoreLocation = 'Cert:\CurrentUser\My'
        # An RFC822/email SAN keeps the certificates realistic for S/MIME.
        TextExtension     = @("2.5.29.17={text}email=$FriendlyName@invalid")
    }
    foreach ($key in $KeyParameters.Keys) {
        $params[$key] = $KeyParameters[$key]
    }

    Write-Host "provision: creating '$FriendlyName'..."
    # Run in a job so a wedged KSP call fails loudly instead of hanging the CI job forever.
    $job = Start-Job -ScriptBlock { param($p) New-SelfSignedCertificate @p } -ArgumentList $params
    try {
        if (Wait-Job $job -Timeout 180) {
            $cert = Receive-Job $job
            Write-Host "provision: created '$FriendlyName' ($($cert.Thumbprint))"
        }
        else {
            throw "New-SelfSignedCertificate timed out after 180s for '$FriendlyName'"
        }
    }
    finally {
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

function New-RsaRegressionCert {
    # RSA keys keep the legacy KeySpec field: it steers CNG key usage agreement and keeps the key
    # usable by CryptoAPI consumers, which mirrors real-world S/MIME certificates. Note that an
    # explicit -Provider must NOT be combined with KeySpec: CertEnroll then takes the legacy
    # provider-type path and fails with NTE_PROV_TYPE_NOT_DEF.
    New-CngKeyCert -Subject 'CN=osclientcerts-smime-rsa' -FriendlyName 'osclientcerts-smime-rsa' `
        -KeyParameters @{
        KeyAlgorithm = 'RSA'
        KeyLength    = 2048
        KeySpec      = 'KeyExchange'
        KeyUsage     = @('DigitalSignature', 'DataEncipherment', 'KeyEncipherment')
    }
}

function New-EcRegressionCert {
    # ECDSA_nistP256 is CNG-only: no KeySpec may be set here (NTE_PROV_TYPE_NOT_DEF otherwise).
    # The default CNG provider guarantees an NCrypt private-key association regardless; the
    # smime_ec_certificate_has_cng_private_key test asserts exactly that at the store level.
    New-CngKeyCert -Subject 'CN=osclientcerts-smime-ec' -FriendlyName 'osclientcerts-smime-ec' `
        -KeyParameters @{
        KeyAlgorithm = 'ECDSA_nistP256'
        KeyUsage     = @('DigitalSignature')
    }
}

New-RsaRegressionCert
New-EcRegressionCert

Write-Host 'provision: regression test certificates ready'
