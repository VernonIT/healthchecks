#Requires -Modules Az.Accounts, Az.Resources, Az.Network, Az.Websites, Az.Monitor, Az.Security, Az.KeyVault

<#
.SYNOPSIS
    Azure App Service Environment (ASE) Security Assessment Script
.DESCRIPTION
    Validates ASE configuration against security best practices for highly secure environments
.PARAMETER ResourceGroupName
    Resource group containing the ASE
.PARAMETER ASEName
    Name of the App Service Environment
.PARAMETER OutputPath
    Path for the HTML report (default: current directory)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$ASEName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ASE-Security-Report.html"
)

# Color codes for console output
$script:PassColor = "Green"
$script:FailColor = "Red"
$script:WarnColor = "Yellow"
$script:InfoColor = "Cyan"

# Results collection
$script:Results = @()
$script:Score = 0
$script:TotalChecks = 0

function Add-CheckResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status, # Pass, Fail, Warning, Info
        [string]$Details,
        [string]$Recommendation = ""
    )
    
    $script:TotalChecks++
    if ($Status -eq "Pass") { $script:Score++ }
    
    $script:Results += [PSCustomObject]@{
        Category = $Category
        Check = $Check
        Status = $Status
        Details = $Details
        Recommendation = $Recommendation
    }
    
    $color = switch ($Status) {
        "Pass" { $PassColor }
        "Fail" { $FailColor }
        "Warning" { $WarnColor }
        default { $InfoColor }
    }
    
    Write-Host "[$Status] $Check" -ForegroundColor $color
    if ($Details) { Write-Host "  → $Details" -ForegroundColor Gray }
}

function Test-AzureConnection {
    Write-Host "`n=== Validating Azure Connection ===" -ForegroundColor $InfoColor
    try {
        $context = Get-AzContext
        if (-not $context) {
            throw "Not connected to Azure"
        }
        Write-Host "Connected to: $($context.Subscription.Name)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
        Write-Host "Please run 'Connect-AzAccount' first" -ForegroundColor Yellow
        return $false
    }
}

function Get-ASEConfiguration {
    Write-Host "`n=== Retrieving ASE Configuration ===" -ForegroundColor $InfoColor
    
    try {
        # Get ASE resource
        $ase = Get-AzResource -ResourceGroupName $ResourceGroupName -Name $ASEName -ResourceType "Microsoft.Web/hostingEnvironments" -ExpandProperties
        
        if (-not $ase) {
            throw "ASE '$ASEName' not found in resource group '$ResourceGroupName'"
        }
        
        Write-Host "Found ASE: $($ase.Name)" -ForegroundColor Green
        Write-Host "Location: $($ase.Location)" -ForegroundColor Gray
        Write-Host "Kind: $($ase.Kind)" -ForegroundColor Gray
        
        return $ase
    }
    catch {
        Write-Host "Error retrieving ASE: $_" -ForegroundColor Red
        throw
    }
}

function Test-NetworkIsolation {
    param($ASE)
    
    Write-Host "`n=== Network Isolation Checks ===" -ForegroundColor $InfoColor
    
    # Check if Internal Load Balancer
    $internalLoadBalancerMode = $ASE.Properties.internalLoadBalancingMode
    if ($internalLoadBalancerMode -eq "Web" -or $internalLoadBalancerMode -eq "Web, Publishing") {
        Add-CheckResult -Category "Network Isolation" -Check "Internal Load Balancer (ILB)" `
            -Status "Pass" -Details "ASE is configured with ILB mode: $internalLoadBalancerMode"
    }
    else {
        Add-CheckResult -Category "Network Isolation" -Check "Internal Load Balancer (ILB)" `
            -Status "Fail" -Details "ASE is using external load balancer" `
            -Recommendation "Configure ASE with Internal Load Balancer for maximum security"
    }
    
    # Check VNet integration
    $vnetResourceId = $ASE.Properties.virtualNetwork.id
    if ($vnetResourceId) {
        Add-CheckResult -Category "Network Isolation" -Check "VNet Integration" `
            -Status "Pass" -Details "ASE is deployed in VNet: $vnetResourceId"
        
        # Get VNet details
        try {
            $vnet = Get-AzResource -ResourceId $vnetResourceId
            $vnetDetails = Get-AzVirtualNetwork -Name $vnet.Name -ResourceGroupName $vnet.ResourceGroupName
            
            # Check subnet size
            $aseSubnet = $vnetDetails.Subnets | Where-Object { $_.Id -eq $ASE.Properties.virtualNetwork.subnet.id }
            if ($aseSubnet) {
                $subnetSize = $aseSubnet.AddressPrefix
                Add-CheckResult -Category "Network Isolation" -Check "Subnet Configuration" `
                    -Status "Info" -Details "ASE subnet: $subnetSize"
            }
            
            # Check for NSG
            if ($aseSubnet.NetworkSecurityGroup) {
                $nsgId = $aseSubnet.NetworkSecurityGroup.Id
                Add-CheckResult -Category "Network Isolation" -Check "Network Security Group" `
                    -Status "Pass" -Details "NSG configured: $($nsgId.Split('/')[-1])"
                
                # Analyze NSG rules
                Test-NSGRules -NSGId $nsgId
            }
            else {
                Add-CheckResult -Category "Network Isolation" -Check "Network Security Group" `
                    -Status "Fail" -Details "No NSG attached to ASE subnet" `
                    -Recommendation "Attach NSG to control inbound/outbound traffic"
            }
        }
        catch {
            Add-CheckResult -Category "Network Isolation" -Check "VNet Analysis" `
                -Status "Warning" -Details "Could not retrieve VNet details: $_"
        }
    }
    else {
        Add-CheckResult -Category "Network Isolation" -Check "VNet Integration" `
            -Status "Fail" -Details "ASE not integrated with VNet"
    }
}

function Test-NSGRules {
    param($NSGId)
    
    try {
        $nsgResource = Get-AzResource -ResourceId $NSGId
        $nsg = Get-AzNetworkSecurityGroup -Name $nsgResource.Name -ResourceGroupName $nsgResource.ResourceGroupName
        
        # Check for default deny
        $hasDefaultDeny = $nsg.SecurityRules | Where-Object { 
            $_.Direction -eq "Inbound" -and 
            $_.Access -eq "Deny" -and 
            $_.SourceAddressPrefix -eq "*" -and
            $_.Priority -gt 4000
        }
        
        if ($hasDefaultDeny) {
            Add-CheckResult -Category "Network Security" -Check "NSG Default Deny Rule" `
                -Status "Pass" -Details "Default deny rule configured"
        }
        else {
            Add-CheckResult -Category "Network Security" -Check "NSG Default Deny Rule" `
                -Status "Warning" -Details "No explicit default deny rule found" `
                -Recommendation "Add a low-priority deny-all rule for defense in depth"
        }
        
        # Check for management port rules (454-455)
        $mgmtRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq "Inbound" -and
            $_.Access -eq "Allow" -and
            ($_.DestinationPortRange -like "*454*" -or $_.DestinationPortRange -like "*455*")
        }
        
        if ($mgmtRules) {
            Add-CheckResult -Category "Network Security" -Check "ASE Management Ports" `
                -Status "Pass" -Details "Management ports (454-455) configured: $($mgmtRules.Count) rule(s)"
        }
        else {
            Add-CheckResult -Category "Network Security" -Check "ASE Management Ports" `
                -Status "Warning" -Details "No explicit rules for management ports" `
                -Recommendation "Ensure ports 454-455 are allowed from App Service management addresses"
        }
        
        # Check for overly permissive rules
        $openRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq "Inbound" -and
            $_.Access -eq "Allow" -and
            $_.SourceAddressPrefix -eq "*" -and
            $_.DestinationPortRange -ne "443" -and
            $_.DestinationPortRange -ne "80"
        }
        
        if ($openRules) {
            Add-CheckResult -Category "Network Security" -Check "Overly Permissive NSG Rules" `
                -Status "Fail" -Details "Found $($openRules.Count) rules allowing traffic from any source" `
                -Recommendation "Restrict source IP ranges to trusted networks only"
        }
        else {
            Add-CheckResult -Category "Network Security" -Check "Overly Permissive NSG Rules" `
                -Status "Pass" -Details "No overly permissive inbound rules detected"
        }
    }
    catch {
        Add-CheckResult -Category "Network Security" -Check "NSG Rule Analysis" `
            -Status "Warning" -Details "Could not analyze NSG rules: $_"
    }
}

function Test-WebApps {
    param($ASE)
    
    Write-Host "`n=== Web App Security Checks ===" -ForegroundColor $InfoColor
    
    try {
        # Get all App Service Plans in the ASE
        $plans = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName | Where-Object {
            $_.HostingEnvironmentProfile.Id -eq $ASE.ResourceId
        }
        
        if (-not $plans) {
            Add-CheckResult -Category "Web Apps" -Check "App Service Plans" `
                -Status "Info" -Details "No App Service Plans found in this ASE"
            return
        }
        
        foreach ($plan in $plans) {
            # Get web apps in this plan
            $webApps = Get-AzWebApp | Where-Object { $_.ServerFarmId -eq $plan.Id }
            
            foreach ($app in $webApps) {
                Test-WebAppSecurity -WebApp $app
            }
        }
    }
    catch {
        Add-CheckResult -Category "Web Apps" -Check "Web App Enumeration" `
            -Status "Warning" -Details "Could not enumerate web apps: $_"
    }
}

function Test-WebAppSecurity {
    param($WebApp)
    
    $appName = $WebApp.Name
    
    # HTTPS Only
    if ($WebApp.HttpsOnly) {
        Add-CheckResult -Category "Web Apps" -Check "$appName - HTTPS Only" `
            -Status "Pass" -Details "HTTPS enforcement enabled"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - HTTPS Only" `
            -Status "Fail" -Details "HTTP traffic allowed" `
            -Recommendation "Enable HTTPS Only in app configuration"
    }
    
    # TLS Version
    $minTlsVersion = $WebApp.SiteConfig.MinTlsVersion
    if ($minTlsVersion -eq "1.2") {
        Add-CheckResult -Category "Web Apps" -Check "$appName - TLS Version" `
            -Status "Pass" -Details "Minimum TLS 1.2 enforced"
    }
    elseif ($minTlsVersion -eq "1.3") {
        Add-CheckResult -Category "Web Apps" -Check "$appName - TLS Version" `
            -Status "Pass" -Details "Minimum TLS 1.3 enforced (excellent)"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - TLS Version" `
            -Status "Fail" -Details "TLS version: $minTlsVersion" `
            -Recommendation "Set minimum TLS version to 1.2 or higher"
    }
    
    # FTP State
    $ftpState = $WebApp.SiteConfig.FtpsState
    if ($ftpState -eq "Disabled" -or $ftpState -eq "FtpsOnly") {
        Add-CheckResult -Category "Web Apps" -Check "$appName - FTP Access" `
            -Status "Pass" -Details "FTP properly restricted: $ftpState"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - FTP Access" `
            -Status "Fail" -Details "FTP state: $ftpState" `
            -Recommendation "Disable FTP or use FTPS only"
    }
    
    # Remote Debugging
    if ($WebApp.SiteConfig.RemoteDebuggingEnabled) {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Remote Debugging" `
            -Status "Fail" -Details "Remote debugging is enabled" `
            -Recommendation "Disable remote debugging in production"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Remote Debugging" `
            -Status "Pass" -Details "Remote debugging disabled"
    }
    
    # Managed Identity
    if ($WebApp.Identity.Type -ne "None") {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Managed Identity" `
            -Status "Pass" -Details "Managed identity enabled: $($WebApp.Identity.Type)"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Managed Identity" `
            -Status "Warning" -Details "No managed identity configured" `
            -Recommendation "Enable managed identity for Azure service authentication"
    }
    
    # Always On (for critical apps)
    if ($WebApp.SiteConfig.AlwaysOn) {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Always On" `
            -Status "Pass" -Details "Always On enabled"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Always On" `
            -Status "Info" -Details "Always On not enabled" `
            -Recommendation "Consider enabling Always On for critical applications"
    }
    
    # IP Restrictions
    $ipRestrictions = $WebApp.SiteConfig.IpSecurityRestrictions
    if ($ipRestrictions -and $ipRestrictions.Count -gt 0) {
        $allowAllRule = $ipRestrictions | Where-Object { $_.IpAddress -eq "Any" -and $_.Action -eq "Allow" }
        if ($allowAllRule) {
            Add-CheckResult -Category "Web Apps" -Check "$appName - IP Restrictions" `
                -Status "Warning" -Details "IP restrictions configured but include 'Allow Any' rule" `
                -Recommendation "Remove 'Allow Any' rule and specify trusted IP ranges"
        }
        else {
            Add-CheckResult -Category "Web Apps" -Check "$appName - IP Restrictions" `
                -Status "Pass" -Details "IP restrictions configured: $($ipRestrictions.Count) rule(s)"
        }
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - IP Restrictions" `
            -Status "Info" -Details "No IP restrictions configured" `
            -Recommendation "Consider adding IP restrictions for additional security"
    }
    
    # Check for Key Vault references
    $appSettings = Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name
    $kvReferences = $appSettings.SiteConfig.AppSettings | Where-Object { $_.Value -like "@Microsoft.KeyVault*" }
    
    if ($kvReferences) {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Key Vault Integration" `
            -Status "Pass" -Details "Using Key Vault references: $($kvReferences.Count) setting(s)"
    }
    else {
        Add-CheckResult -Category "Web Apps" -Check "$appName - Key Vault Integration" `
            -Status "Info" -Details "No Key Vault references detected" `
            -Recommendation "Store secrets in Key Vault and reference them in app settings"
    }
}

function Test-Monitoring {
    param($ASE)
    
    Write-Host "`n=== Monitoring & Logging Checks ===" -ForegroundColor $InfoColor
    
    try {
        # Check diagnostic settings
        $diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $ASE.ResourceId -ErrorAction SilentlyContinue
        
        if ($diagnosticSettings) {
            Add-CheckResult -Category "Monitoring" -Check "Diagnostic Settings" `
                -Status "Pass" -Details "Diagnostic logging configured: $($diagnosticSettings.Count) setting(s)"
            
            foreach ($setting in $diagnosticSettings) {
                if ($setting.WorkspaceId) {
                    Add-CheckResult -Category "Monitoring" -Check "Log Analytics Integration" `
                        -Status "Pass" -Details "Logs sent to Log Analytics workspace"
                }
                if ($setting.StorageAccountId) {
                    Add-CheckResult -Category "Monitoring" -Check "Storage Account Archival" `
                        -Status "Pass" -Details "Logs archived to Storage Account"
                }
            }
        }
        else {
            Add-CheckResult -Category "Monitoring" -Check "Diagnostic Settings" `
                -Status "Fail" -Details "No diagnostic settings configured" `
                -Recommendation "Enable diagnostic logging to Log Analytics workspace"
        }
    }
    catch {
        Add-CheckResult -Category "Monitoring" -Check "Diagnostic Settings" `
            -Status "Warning" -Details "Could not retrieve diagnostic settings: $_"
    }
    
    # Check for Security Center
    try {
        $securityContacts = Get-AzSecurityContact -ErrorAction SilentlyContinue
        if ($securityContacts) {
            Add-CheckResult -Category "Monitoring" -Check "Security Center Contacts" `
                -Status "Pass" -Details "Security contacts configured"
        }
        else {
            Add-CheckResult -Category "Monitoring" -Check "Security Center Contacts" `
                -Status "Warning" -Details "No security contacts configured" `
                -Recommendation "Configure security contacts in Microsoft Defender for Cloud"
        }
    }
    catch {
        Add-CheckResult -Category "Monitoring" -Check "Security Center" `
            -Status "Info" -Details "Could not check Security Center configuration"
    }
}

function Test-Compliance {
    param($ASE)
    
    Write-Host "`n=== Compliance & Governance Checks ===" -ForegroundColor $InfoColor
    
    # Check for resource locks
    try {
        $locks = Get-AzResourceLock -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if ($locks) {
            Add-CheckResult -Category "Compliance" -Check "Resource Locks" `
                -Status "Pass" -Details "Resource locks configured: $($locks.Count) lock(s)"
        }
        else {
            Add-CheckResult -Category "Compliance" -Check "Resource Locks" `
                -Status "Warning" -Details "No resource locks found" `
                -Recommendation "Apply CanNotDelete locks to production resources"
        }
    }
    catch {
        Add-CheckResult -Category "Compliance" -Check "Resource Locks" `
            -Status "Info" -Details "Could not check resource locks"
    }
    
    # Check for tags
    if ($ASE.Tags -and $ASE.Tags.Count -gt 0) {
        Add-CheckResult -Category "Compliance" -Check "Resource Tagging" `
            -Status "Pass" -Details "Tags configured: $($ASE.Tags.Count) tag(s)"
    }
    else {
        Add-CheckResult -Category "Compliance" -Check "Resource Tagging" `
            -Status "Warning" -Details "No tags configured" `
            -Recommendation "Add tags for cost tracking and governance (e.g., Environment, Owner, CostCenter)"
    }
    
    # Check for Azure Policy assignments
    try {
        $policyAssignments = Get-AzPolicyAssignment -Scope "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName" -ErrorAction SilentlyContinue
        if ($policyAssignments) {
            Add-CheckResult -Category "Compliance" -Check "Azure Policy" `
                -Status "Pass" -Details "Policy assignments found: $($policyAssignments.Count) assignment(s)"
        }
        else {
            Add-CheckResult -Category "Compliance" -Check "Azure Policy" `
                -Status "Info" -Details "No specific policy assignments at resource group level" `
                -Recommendation "Consider using Azure Policy to enforce security standards"
        }
    }
    catch {
        Add-CheckResult -Category "Compliance" -Check "Azure Policy" `
            -Status "Info" -Details "Could not check policy assignments"
    }
}

function Generate-HTMLReport {
    param($ASE)
    
    Write-Host "`n=== Generating Report ===" -ForegroundColor $InfoColor
    
    $compliancePercentage = [math]::Round(($script:Score / $script:TotalChecks) * 100, 2)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>ASE Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; border-bottom: 2px solid #eee; padding-bottom: 5px; }
        .summary { background: #e8f4fd; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .score { font-size: 48px; font-weight: bold; color: #0078d4; }
        .score-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f9f9f9; }
        .status { padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; min-width: 70px; text-align: center; }
        .pass { background: #d4edda; color: #155724; }
        .fail { background: #f8d7da; color: #721c24; }
        .warning { background: #fff3cd; color: #856404; }
        .info { background: #d1ecf1; color: #0c5460; }
        .recommendation { color: #666; font-style: italic; font-size: 0.9em; margin-top: 5px; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .metadata-item { margin: 5px 0; }
        .category-section { margin: 30px 0; }
        .gauge { width: 200px; height: 200px; margin: 20px auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Azure ASE Security Assessment Report</h1>
        
        <div class="metadata">
            <div class="metadata-item"><strong>ASE Name:</strong> $($ASE.Name)</div>
            <div class="metadata-item"><strong>Resource Group:</strong> $ResourceGroupName</div>
            <div class="metadata-item"><strong>Location:</strong> $($ASE.Location)</div>
            <div class="metadata-item"><strong>ASE Type:</strong> $($ASE.Kind)</div>
            <div class="metadata-item"><strong>Report Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div style="text-align: center;">
                <div class="score">$compliancePercentage%</div>
                <div class="score-label">Security Compliance Score</div>
                <p style="margin-top: 15px;">$script:Score out of $script:TotalChecks checks passed</p>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"@
    
    # Group results by category
    $categories = $script:Results | Group-Object -Property Category
    
    foreach ($category in $categories) {
        $html += @"
        <div class="category-section">
            <h3>$($category.Name)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Check</th>
                        <th style="width: 100px;">Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($result in $category.Group) {
            $statusClass = $result.Status.ToLower()
            $html += @"
                    <tr>
                        <td><strong>$($result.Check)</strong></td>
                        <td><span class="status $statusClass">$($result.Status)</span></td>
                        <td>
                            $($result.Details)
"@
            if ($result.Recommendation) {
                $html += @"
                            <div class="recommendation">💡 $($result.Recommendation)</div>
"@
            }
            $html += @"
                        </td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }
    
    # Summary statistics
    $passCount = ($script:Results | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount = ($script:Results | Where-Object { $_.Status -eq "Fail" }).Count
    $warnCount = ($script:Results | Where-Object { $_.Status -eq "Warning" }).Count
    $infoCount = ($script:Results | Where-Object { $_.Status -eq "Info" }).Count
    
    $html += @"
        <h2>Summary Statistics</h2>
        <table>
            <tr>
                <td><span class="status pass">Pass</span></td>
                <td>$passCount</td>
            </tr>
            <tr>
                <td><span class="status fail">Fail</span></td>
                <td>$failCount</td>
            </tr>
            <tr>
                <td><span class="status warning">Warning</span></td>
                <td>$warnCount</td>
            </tr>
            <tr>
                <td><span class="status info">Info</span></td>
                <td>$infoCount</td>
            </tr>
        </table>
        
        <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-left: 4px solid #0078d4;">
            <h3>Next Steps</h3>
            <p>Review all <strong>Fail</strong> and <strong>Warning</strong> items above and implement the recommended changes.</p>
            <p>For items marked as <strong>Info</strong>, evaluate whether they apply to your security requirements.</p>
            <p>Re-run this assessment after making changes to track your progress.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
}

# Main execution
try {
    Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║   Azure App Service Environment Security Assessment Script    ║
║                                                               ║
║   This script validates your ASE configuration against        ║
║   security best practices for highly secure environments     ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    
    # Check Azure connection
    if (-not (Test-AzureConnection)) {
        exit 1
    }
    
    # Get ASE configuration
    $ase = Get-ASEConfiguration
    
    # Run security checks
    Test-NetworkIsolation -ASE $ase
    Test-WebApps -ASE $ase
    Test-Monitoring -ASE $ase
    Test-Compliance -ASE $ase
    
    # Generate report
    Generate-HTMLReport -ASE $ase
    
    # Display summary
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ASSESSMENT COMPLETE                        ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $compliancePercentage = [math]::Round(($script:Score / $script:TotalChecks) * 100, 2)
    Write-Host "`nCompliance Score: " -NoNewline
    
    if ($compliancePercentage -ge 80) {
        Write-Host "$compliancePercentage% ✓" -ForegroundColor Green
    }
    elseif ($compliancePercentage -ge 60) {
        Write-Host "$compliancePercentage% ⚠" -ForegroundColor Yellow
    }
    else {
        Write-Host "$compliancePercentage% ✗" -ForegroundColor Red
    }
    
    Write-Host "Checks Passed: $script:Score / $script:TotalChecks`n"
    
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
    Write-Host "`nOpen the report in your browser for detailed findings and recommendations.`n"
}
catch {
    Write-Host "`n❌ Script execution failed: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}