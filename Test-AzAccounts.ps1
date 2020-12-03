<#
.SYNOPSIS
    This test is for testing new Az.Accounts modules.

    IMPORTANT!
    1. For this test to work, install the following "SpnCert.pfx" file to "Cert:\LocalMachine\My" from the following link:
    Online
    https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/46d8b0b3-665f-4745-9fae-95ad05d82e15/resourceGroups/SpnRg/providers/Microsoft.KeyVault/vaults/SpnKvRedmond/certificates
    
    On the Microsoft Network:
    \\baladev\public\wei

    2. Get the password to SpnCert.pfx from someone on the AzureStack DevExp team, or check the following location:
    \\baladev\public\wei

    3. Convert the password to secure string:
    $pass = ConvertTo-SecureString -String $unsecurePass -AsPlainText -Force

    2. Then import it:
    Import-PfxCertificate -FilePath C:\SpnCert.pfx -CertStoreLocation Cert:\LocalMachine\My -Password $pass
#>
param
(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $EnvironmentName = 'az-accounts-test',

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [ValidateScript({ $_.Scheme -eq [System.Uri]::UriSchemeHttps })]
    [System.Uri] $ResourceManagerEndpoint,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [string] $ClientIDForSecret,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [string] $ClientSecret,
<#
TODO: Add test for certificate-based SP
    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [string] $ClientIDForCertificate,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^([0-9A-Fa-f]{2})*$')]
    [string] $CertificateThumbprint,
#>
    # Optional subscription to select as the active / default subscription.
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionId
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

function Test
{
    Param
    (
        [String] $TestName,
        [ScriptBlock] $TestBlock
    )

    Write-Verbose -Message "[START]: ${TestName}" -Verbose
    try
    {
        $TestBlock.Invoke()
    }
    catch
    {
        Write-Error $_
    }
    Write-Verbose -Message "[END]: ${TestName}`n" -Verbose
}

function AssertEquals
{
    Param
    (
        [Object] $Value1,
        [Object] $Value2,
        [string] $Description
    )

    if ($Value1 -ne $Value2)
    {
        throw "The Value1 ${Value1} does not match the Value2 ${Value2}."
    }
    else {
        Write-Verbose -Message "The ${Description} test is successful." -Verbose
    }
}

function AssertNotEquals
{
    Param
    (
        [Object] $Value1,
        [Object] $Value2,
        [string] $Description
    )

    if ($Value1 -eq $Value2)
    {
        throw "The Value1 ${Value1} should not match the Value2 ${Value2}."
    }
    else {
        Write-Verbose -Message "The ${Description} test is successful." -Verbose
    }
}

$TestAddAzEnvironment =
{
    Write-Verbose -Message "Running Add-AzEnvironment..." -Verbose
    Add-AzEnvironment -Name $EnvironmentName -ARMEndpoint $ResourceManagerEndpoint -ErrorAction Stop
    $getEnvironment = Get-AzEnvironment -Name $EnvironmentName
    if ($null -eq $getEnvironment)
    {
        throw "Could not find the environment ${EnvironmentName} after adding it."
    }
    Get-AzEnvironment -Name $EnvironmentName | Format-List -Property *
}

$TestServicePrincipalSecretLogin =
{
    $sleepSecondsUnit = 5
    $maxSleepSeconds = 30
    $currentSeconds = 0

    # $currentSeconds should not be compared to a multiple of $sleepSecondUnit since it won't tell us if the operation was successful because it could be that
    # it was successful at the last second. If the $currentSeconds is ($maxSleepSeconds+1) or over, we know for sure the operation took too long.
    while ($currentSeconds -lt $maxSleepSeconds + 1)
    {
        Write-Verbose -Message "Connecting to service principal, ignore errors until timeout. $($maxSleepSeconds - $currentSeconds) seconds until timeout error." -Verbose
        try
        {
            $servicePrincipalSecurePassword = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
            $servicePrincipalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientIDForSecret, $servicePrincipalSecurePassword
            
            if ($null -eq $SubscriptionId)
            {
                Connect-AzAccount -Environment $EnvironmentName -ServicePrincipal -Credential $servicePrincipalCredential -TenantId $TenantId
            }
            else
            {
                Connect-AzAccount -Environment $EnvironmentName -ServicePrincipal -Credential $servicePrincipalCredential -TenantId $TenantId -Subscription $SubscriptionId
            }
            
            Start-Sleep -s $sleepSecondsUnit
            $currentSeconds += $sleepSecondsUnit

            if (($null -eq (get-AzContext)) -or ($ClientIDForSecret -ne ((Get-AzContext).Account.Id)))
            {
                throw "Failed to connect to service principal with client ID ${clientIDForSecret}. Trying again..."
            }

            Write-Verbose -Message "Current context:" -Verbose
            Get-AzContext | Format-List -Property * | Out-String | Write-Verbose -Verbose
            Write-Verbose -Message "Current account:" -Verbose
            $(Get-AzContext).Account | Format-List -Property * | Out-String | Write-Verbose -Verbose

            break
        }
        catch
        {
            Write-Verbose -Message $_ -Verbose
        }
    }

    if ($currentSeconds -ge $maxSleepSeconds + 1)
    {
        throw "Connect-AzAccount command timed out."
    }
}
<#
TODO: Add test for certificate-based SP
$TestServicePrincipalCertificateLogin =
{
    $sleepSecondsUnit = 5
    $maxSleepSeconds = 30 
    $currentSeconds = 0

    # $currentSeconds should not be compared to a multiple of $sleepSecondUnit since it won't tell us if the operation was successful because it could be that
    # it was successful at the last second. If the $currentSeconds is ($maxSleepSeconds+1) or over, we know for sure the operation took too long.
    while ($currentSeconds -lt $maxSleepSeconds + 1)
    {
        Write-Verbose "Connecting to service principal, ignore errors until timeout. $($maxSleepSeconds - $currentSeconds) seconds until timeout error." -Verbose
        try
        {
            if ($null -eq $SubscriptionId)
            {
                Connect-AzAccount -Environment $EnvironmentName -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationId $clientIDForCertificate -TenantId $TenantId
            }
            else
            {
                Connect-AzAccount -Environment $EnvironmentName -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationId $clientIDForCertificate -TenantId $TenantId -Subscription $SubscriptionId
            }

            Start-Sleep -s $sleepSecondsUnit
            $currentSeconds += $sleepSecondsUnit

            if (($null -eq (get-AzContext)) -or ($clientIDForCertificate -ne ((Get-AzContext).Account.Id)))
            {
                throw "Failed to connect to service principal with client ID ${ClientIdForCertificate}. Try again..."
            }

            Write-Verbose -Message "Current context:" -Verbose
            Get-AzContext | Format-List -Property * | Out-String | Write-Verbose -Verbose
            Write-Verbose -Message "Current account:" -Verbose
            $(Get-AzContext).Account | Format-List -Property * | Out-String | Write-Verbose -Verbose
            break
        }
        catch
        {
            Write-Verbose -Message $_ -Verbose
        }
    }

    if ($currentSeconds -ge $maxSleepSeconds + 1)
    {
        throw "Connect-AzAccount command timed out."
    }
}
#>
$TestGetAzContext =
{
    Write-Verbose -Message "Running Get-AzContext..." -Verbose
    Get-AzContext | Format-List | Out-String | Write-Verbose -Verbose
}

$TestGetAzTenant =
{
    Write-Verbose -Message "Running Get-AzTenant..." -Verbose
    $azTenant = Get-AzTenant
    $azTenant | Format-List | Out-String | Write-Verbose -Verbose

    $environment = Get-AzEnvironment | Where-Object {$_.Name -eq "${EnvironmentName}"}
    $tenantName = $environment.ActiveDirectoryServiceEndpointResourceId.split("/")[2].split(".", 2)[1]

    $webClient = new-object system.net.webclient
    $JSON=$webClient.DownloadString("https://login.microsoftonline.com/${tenantName}/.well-known/openid-configuration") `
        | ConvertFrom-Json
    $tenantID = $JSON.token_endpoint.split("/")[3]

    AssertEquals -Value1 $azTenant.Id -Value2 $tenantID -Description "Tenant ID Comparison" -ErrorAction Continue
}

$TestAzContextAutosave =
{
    $originalContext = Get-AzContextAutosaveSetting

    # context autosave already disabled
    if ($originalContext.ContextFile -eq "none")
    {
        # Test context autosave is disabled in new ps session
        $job = Start-Job -ScriptBlock { Get-AzContext }
        $context = Receive-Job -Job $job -Wait
        AssertEquals -Value1 $context -Value2 $null -Description "Disable Context" -ErrorAction Continue

        Enable-AzContextAutosave

        $job = Start-Job -ScriptBlock { Get-AzContext }
        $context = Receive-Job -Job $job -Wait
        AssertNotEquals -Value1 $context -Value2 $null -Description "Enable Context" -ErrorAction Continue

        Disable-AzContextAutosave
    }
    # context autosave already enabled
    else
    {
        # Test context autosave is disabled in new ps session
        $job = Start-Job -ScriptBlock { Get-AzContext }
        $context = Receive-Job -Job $job -Wait
        AssertNotEquals -Value1 $context -Value2 $null -Description "Enabled Context" -ErrorAction Continue

        Disable-AzContextAutosave

        $job = Start-Job -ScriptBlock { Get-AzContext }
        $context = Receive-Job -Job $job -Wait
        AssertEquals -Value1 $context -Value2 $null -Description "Disabled Context" -ErrorAction Continue

        Enable-AzContextAutosave
    }
}

function Main
{
    Import-Module Az.Accounts

    Test -TestName "TestAddAzEnvironment" -TestBlock $TestAddAzEnvironment
    # TODO: Add test for certificate-based SP
    # Test -TestName "TestServicePrincipalCertificateLogin" -TestBlock $TestServicePrincipalCertificateLogin
    Test -TestName "TestServicePrincipalSecretLogin" -TestBlock $TestServicePrincipalSecretLogin
    Test -TestName "TestGetAzContext" -TestBlock $TestGetAzContext
    Test -TestName "TestGetAzTenant" -TestBlock $TestGetAzTenant
    Test -TestName "TestAzContextAutosave" -TestBlock $TestAzContextAutosave
}

Main