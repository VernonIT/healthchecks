#!/bin/bash

#===============================================================================
# Azure App Service Environment (ASE) Security Assessment Script
#
# DESCRIPTION:
#   Validates ASE configuration against security best practices for highly 
#   secure environments using Azure CLI
#
# USAGE:
#   ./ase-security-audit.sh -g <resource-group> -n <ase-name> [-o <output-path>]
#
# REQUIREMENTS:
#   - Azure CLI (az) installed and logged in
#   - jq for JSON parsing
#===============================================================================

set -euo pipefail

# Enable debug mode with -d flag
DEBUG=false

# Default values
OUTPUT_PATH="./ASE-Security-Report.html"
RESOURCE_GROUP=""
ASE_NAME=""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Results tracking
declare -a RESULTS
SCORE=0
TOTAL_CHECKS=0

#===============================================================================
# Helper Functions
#===============================================================================

print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_info() {
    echo -e "${GRAY}$1${NC}"
}

print_debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${GRAY}[DEBUG] $1${NC}"
    fi
}

usage() {
    cat << EOF
Usage: $0 -g <resource-group> -n <ase-name> [-o <output-path>] [-d]

Required:
    -g    Resource group name containing the ASE
    -n    App Service Environment name

Optional:
    -o    Output path for HTML report (default: ./ASE-Security-Report.html)
    -d    Enable debug mode (verbose output)
    -h    Show this help message

Example:
    $0 -g prod-rg -n prod-ase -o /tmp/report.html
EOF
    exit 1
}

add_check_result() {
    local category="$1"
    local check="$2"
    local status="$3"
    local details="$4"
    local recommendation="${5:-}"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [[ "$status" == "Pass" ]]; then
        SCORE=$((SCORE + 1))
    fi
    
    # Store result (using | as delimiter to avoid JSON escaping issues)
    RESULTS+=("${category}|${check}|${status}|${details}|${recommendation}")
    
    # Print to console
    case "$status" in
        "Pass")
            echo -e "${GREEN}[Pass]${NC} $check"
            ;;
        "Fail")
            echo -e "${RED}[Fail]${NC} $check"
            ;;
        "Warning")
            echo -e "${YELLOW}[Warning]${NC} $check"
            ;;
        "Info")
            echo -e "${CYAN}[Info]${NC} $check"
            ;;
    esac
    
    if [[ -n "$details" ]]; then
        print_info "  → $details"
    fi
}

check_dependencies() {
    print_header "=== Checking Dependencies ==="
    
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI (az) is not installed"
        print_info "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed"
        print_info "Install with: apt-get install jq (Ubuntu) or brew install jq (macOS)"
        exit 1
    fi
    
    print_success "✓ All dependencies found"
}

check_azure_login() {
    print_header "=== Validating Azure Connection ==="
    
    if ! az account show &> /dev/null; then
        print_error "Not logged in to Azure"
        print_info "Please run: az login"
        exit 1
    fi
    
    local subscription_name
    subscription_name=$(az account show --query "name" -o tsv)
    print_success "Connected to: $subscription_name"
}

#===============================================================================
# ASE Configuration Retrieval
#===============================================================================

get_ase_config() {
    print_header "=== Retrieving ASE Configuration ==="
    
    # Get ASE resource
    ASE_JSON=$(az resource show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$ASE_NAME" \
        --resource-type "Microsoft.Web/hostingEnvironments" \
        2>/dev/null || echo "")

    # Validate ASE_JSON is valid JSON
    if ! echo "$ASE_JSON" | jq empty 2>/dev/null; then
        print_error "ASE resource output is not valid JSON. Output: $ASE_JSON"
        exit 1
    fi

    if [[ -z "$ASE_JSON" ]]; then
        print_error "ASE '$ASE_NAME' not found in resource group '$RESOURCE_GROUP'"
        exit 1
    fi

    local ase_location
    local ase_kind
    ase_location=$(echo "$ASE_JSON" | jq -r '.location')
    ase_kind=$(echo "$ASE_JSON" | jq -r '.kind // "Not specified"')

    print_success "Found ASE: $ASE_NAME"
    print_info "Location: $ase_location"
    print_info "Kind: $ase_kind"

    # Store ASE ID for later use
    ASE_ID=$(echo "$ASE_JSON" | jq -r '.id')
}

#===============================================================================
# Network Isolation Checks
#===============================================================================

test_network_isolation() {
    print_header "=== Network Isolation Checks ==="
    
    print_debug "Checking Internal Load Balancer mode..."
    
    # Check Internal Load Balancer mode
    local ilb_mode
    ilb_mode=$(echo "$ASE_JSON" | jq -r '.properties.internalLoadBalancingMode // "None"')
    
    print_debug "ILB Mode: $ilb_mode"
    
    if [[ "$ilb_mode" == "Web" ]] || [[ "$ilb_mode" == "Web, Publishing" ]]; then
        add_check_result "Network Isolation" "Internal Load Balancer (ILB)" \
            "Pass" "ASE is configured with ILB mode: $ilb_mode"
    else
        add_check_result "Network Isolation" "Internal Load Balancer (ILB)" \
            "Fail" "ASE is using external load balancer: $ilb_mode" \
            "Configure ASE with Internal Load Balancer for maximum security"
    fi
    
    print_debug "Checking VNet integration..."
    
    # Check VNet integration
    local vnet_id
    vnet_id=$(echo "$ASE_JSON" | jq -r '.properties.virtualNetwork.id // ""')
    
    print_debug "VNet ID: $vnet_id"
    
    if [[ -n "$vnet_id" && "$vnet_id" != "null" ]]; then
        add_check_result "Network Isolation" "VNet Integration" \
            "Pass" "ASE is deployed in VNet: ${vnet_id##*/}"
        
        # Get VNet and subnet details
        test_vnet_configuration "$vnet_id"
    else
        add_check_result "Network Isolation" "VNet Integration" \
            "Fail" "ASE not integrated with VNet"
    fi
}

test_vnet_configuration() {
    local vnet_id="$1"
    
    # Validate vnet_id is not empty or null
    if [[ -z "$vnet_id" || "$vnet_id" == "null" ]]; then
        return
    fi
    
    # Extract VNet resource group and name - handle different ID formats
    local vnet_rg
    local vnet_name
    
    # VNet ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{name}
    vnet_rg=$(echo "$vnet_id" | cut -d'/' -f5)
    vnet_name=$(echo "$vnet_id" | cut -d'/' -f9)
    
    # Validate extracted values
    if [[ -z "$vnet_rg" || -z "$vnet_name" || "$vnet_rg" == "null" || "$vnet_name" == "null" ]]; then
        add_check_result "Network Isolation" "VNet Configuration" \
            "Warning" "Could not parse VNet ID: $vnet_id"
        return
    fi
    
    # Get subnet ID - handle both old and new ASE JSON structures
    local subnet_id
    subnet_id=$(echo "$ASE_JSON" | jq -r '.properties.virtualNetwork.subnet.id // .properties.virtualNetwork.subnetResourceId // ""')
    
    if [[ -z "$subnet_id" || "$subnet_id" == "null" ]]; then
        add_check_result "Network Isolation" "Subnet Configuration" \
            "Warning" "Could not determine ASE subnet"
        return
    fi
    
    local subnet_name
    subnet_name=$(echo "$subnet_id" | cut -d'/' -f11)
    
    # Get subnet details
    local subnet_json
    subnet_json=$(az network vnet subnet show \
        --resource-group "$vnet_rg" \
        --vnet-name "$vnet_name" \
        --name "$subnet_name" \
        2>/dev/null || echo "")

    # Validate subnet_json is valid JSON before using jq
    if ! echo "$subnet_json" | jq empty 2>/dev/null; then
        print_warning "Subnet details output is not valid JSON. Skipping subnet/NSG checks. Output: $subnet_json"
        return
    fi

    if [[ -n "$subnet_json" ]]; then
        local address_prefix
        address_prefix=$(echo "$subnet_json" | jq -r '.addressPrefix')

        add_check_result "Network Isolation" "Subnet Configuration" \
            "Info" "ASE subnet: $address_prefix"

        # Check for NSG (ensure networkSecurityGroup is an object)
        local nsg_id
        nsg_id=""
        if echo "$subnet_json" | jq -e '.networkSecurityGroup | type == "object"' >/dev/null 2>&1; then
            nsg_id=$(echo "$subnet_json" | jq -r '.networkSecurityGroup.id // ""')
        fi

        if [[ -n "$nsg_id" ]]; then
            local nsg_name
            nsg_name=$(echo "$nsg_id" | cut -d'/' -f9)

            add_check_result "Network Isolation" "Network Security Group" \
                "Pass" "NSG configured: $nsg_name"

            test_nsg_rules "$nsg_id"
        else
            add_check_result "Network Isolation" "Network Security Group" \
                "Fail" "No NSG attached to ASE subnet" \
                "Attach NSG to control inbound/outbound traffic"
        fi
    fi
}

test_nsg_rules() {
    local nsg_id="$1"
    
    local nsg_rg
    local nsg_name
    nsg_rg=$(echo "$nsg_id" | cut -d'/' -f5)
    nsg_name=$(echo "$nsg_id" | cut -d'/' -f9)
    
    local nsg_json
    nsg_json=$(az network nsg show \
        --resource-group "$nsg_rg" \
        --name "$nsg_name" \
        2>/dev/null || echo "")
    
    if [[ -z "$nsg_json" ]]; then
        return
    fi
    
    # Check for default deny rule
    local default_deny_count
    default_deny_count=$(echo "$nsg_json" | jq '[.securityRules[] | select(
        .direction == "Inbound" and 
        .access == "Deny" and 
        .sourceAddressPrefix == "*" and
        .priority > 4000
    )] | length')
    
    if [[ "$default_deny_count" -gt 0 ]]; then
        add_check_result "Network Security" "NSG Default Deny Rule" \
            "Pass" "Default deny rule configured"
    else
        add_check_result "Network Security" "NSG Default Deny Rule" \
            "Warning" "No explicit default deny rule found" \
            "Add a low-priority deny-all rule for defense in depth"
    fi
    
    # Check for management port rules (454-455)
    local mgmt_rules_count
    mgmt_rules_count=$(echo "$nsg_json" | jq '[.securityRules[] | select(
        .direction == "Inbound" and 
        .access == "Allow" and
        (.destinationPortRange | tostring | test("454|455"))
    )] | length')
    
    if [[ "$mgmt_rules_count" -gt 0 ]]; then
        add_check_result "Network Security" "ASE Management Ports" \
            "Pass" "Management ports (454-455) configured: $mgmt_rules_count rule(s)"
    else
        add_check_result "Network Security" "ASE Management Ports" \
            "Warning" "No explicit rules for management ports" \
            "Ensure ports 454-455 are allowed from App Service management addresses"
    fi
    
    # Check for overly permissive rules
    local open_rules_count
    open_rules_count=$(echo "$nsg_json" | jq '[.securityRules[] | select(
        .direction == "Inbound" and 
        .access == "Allow" and 
        .sourceAddressPrefix == "*" and
        .destinationPortRange != "443" and
        .destinationPortRange != "80"
    )] | length')
    
    if [[ "$open_rules_count" -gt 0 ]]; then
        add_check_result "Network Security" "Overly Permissive NSG Rules" \
            "Fail" "Found $open_rules_count rules allowing traffic from any source" \
            "Restrict source IP ranges to trusted networks only"
    else
        add_check_result "Network Security" "Overly Permissive NSG Rules" \
            "Pass" "No overly permissive inbound rules detected"
    fi
}

#===============================================================================
# Web App Security Checks
#===============================================================================

test_web_apps() {
    print_header "=== Web App Security Checks ==="
    
    # Get all App Service Plans in the ASE across ALL resource groups in subscription
    print_info "Searching for App Service Plans across all resource groups..."
    local plans_json
    plans_json=$(az appservice plan list \
        --query "[?hostingEnvironmentProfile.id=='$ASE_ID']" \
        2>/dev/null || echo "[]")
    
    local plans_count
    plans_count=$(echo "$plans_json" | jq 'length')
    
    if [[ "$plans_count" -eq 0 ]]; then
        add_check_result "Web Apps" "App Service Plans" \
            "Info" "No App Service Plans found in this ASE"
        return
    fi
    
    print_info "Found $plans_count App Service Plan(s) in ASE"
    
    # Iterate through plans and get web apps
    local plan_count
    plan_count=$(echo "$plans_json" | jq 'length')
    
    for ((i=0; i<plan_count; i++)); do
        local plan_id
        plan_id=$(echo "$plans_json" | jq -r ".[$i].id")
        
        [[ -z "$plan_id" || "$plan_id" == "null" ]] && continue
        
        # Get web apps for this plan (searches all resource groups)
        local apps_json
        apps_json=$(az webapp list --query "[?serverFarmId=='$plan_id']" 2>/dev/null || echo "[]")
        
        local apps_count
        apps_count=$(echo "$apps_json" | jq 'length')
        
        if [[ "$apps_count" -gt 0 ]]; then
            print_info "Found $apps_count app(s) in plan: ${plan_id##*/}"
            
            # Process each app with its resource group
            for ((j=0; j<apps_count; j++)); do
                local app_name
                local app_rg
                app_name=$(echo "$apps_json" | jq -r ".[$j].name")
                app_rg=$(echo "$apps_json" | jq -r ".[$j].resourceGroup")
                
                [[ -z "$app_name" || "$app_name" == "null" ]] && continue
                [[ -z "$app_rg" || "$app_rg" == "null" ]] && continue
                
                test_web_app_security "$app_name" "$app_rg"
            done
        fi
    done
}

test_web_app_security() {
    local app_name="$1"
    local app_rg="$2"
    
    local app_json
    app_json=$(az webapp show \
        --name "$app_name" \
        --resource-group "$app_rg" \
        2>/dev/null || echo "")
    
    if [[ -z "$app_json" ]]; then
        return
    fi
    
    # HTTPS Only
    local https_only
    https_only=$(echo "$app_json" | jq -r '.httpsOnly')
    
    if [[ "$https_only" == "true" ]]; then
        add_check_result "Web Apps" "$app_name - HTTPS Only" \
            "Pass" "HTTPS enforcement enabled"
    else
        add_check_result "Web Apps" "$app_name - HTTPS Only" \
            "Fail" "HTTP traffic allowed" \
            "Enable HTTPS Only in app configuration"
    fi
    
    # TLS Version
    local min_tls
    min_tls=$(echo "$app_json" | jq -r '.siteConfig.minTlsVersion // "1.0"')
    
    if [[ "$min_tls" == "1.2" ]]; then
        add_check_result "Web Apps" "$app_name - TLS Version" \
            "Pass" "Minimum TLS 1.2 enforced"
    elif [[ "$min_tls" == "1.3" ]]; then
        add_check_result "Web Apps" "$app_name - TLS Version" \
            "Pass" "Minimum TLS 1.3 enforced (excellent)"
    else
        add_check_result "Web Apps" "$app_name - TLS Version" \
            "Fail" "TLS version: $min_tls" \
            "Set minimum TLS version to 1.2 or higher"
    fi
    
    # FTP State
    local ftp_state
    ftp_state=$(echo "$app_json" | jq -r '.siteConfig.ftpsState // "AllAllowed"')
    
    if [[ "$ftp_state" == "Disabled" ]] || [[ "$ftp_state" == "FtpsOnly" ]]; then
        add_check_result "Web Apps" "$app_name - FTP Access" \
            "Pass" "FTP properly restricted: $ftp_state"
    else
        add_check_result "Web Apps" "$app_name - FTP Access" \
            "Fail" "FTP state: $ftp_state" \
            "Disable FTP or use FTPS only"
    fi
    
    # Remote Debugging
    local remote_debug
    remote_debug=$(echo "$app_json" | jq -r '.siteConfig.remoteDebuggingEnabled')
    
    if [[ "$remote_debug" == "true" ]]; then
        add_check_result "Web Apps" "$app_name - Remote Debugging" \
            "Fail" "Remote debugging is enabled" \
            "Disable remote debugging in production"
    else
        add_check_result "Web Apps" "$app_name - Remote Debugging" \
            "Pass" "Remote debugging disabled"
    fi
    
    # Managed Identity
    local identity_type
    identity_type=$(echo "$app_json" | jq -r '.identity.type // "None"')
    
    if [[ "$identity_type" != "None" ]]; then
        add_check_result "Web Apps" "$app_name - Managed Identity" \
            "Pass" "Managed identity enabled: $identity_type"
    else
        add_check_result "Web Apps" "$app_name - Managed Identity" \
            "Warning" "No managed identity configured" \
            "Enable managed identity for Azure service authentication"
    fi
    
    # Always On
    local always_on
    always_on=$(echo "$app_json" | jq -r '.siteConfig.alwaysOn')
    
    if [[ "$always_on" == "true" ]]; then
        add_check_result "Web Apps" "$app_name - Always On" \
            "Pass" "Always On enabled"
    else
        add_check_result "Web Apps" "$app_name - Always On" \
            "Info" "Always On not enabled" \
            "Consider enabling Always On for critical applications"
    fi
    
    # IP Restrictions
    local ip_restrictions
    ip_restrictions=$(echo "$app_json" | jq '.siteConfig.ipSecurityRestrictions // []')
    local ip_count
    ip_count=$(echo "$ip_restrictions" | jq 'length')
    
    if [[ "$ip_count" -gt 0 ]]; then
        local allow_all_count
        allow_all_count=$(echo "$ip_restrictions" | jq '[.[] | select(.ipAddress == "Any" and .action == "Allow")] | length')
        
        if [[ "$allow_all_count" -gt 0 ]]; then
            add_check_result "Web Apps" "$app_name - IP Restrictions" \
                "Warning" "IP restrictions configured but include 'Allow Any' rule" \
                "Remove 'Allow Any' rule and specify trusted IP ranges"
        else
            add_check_result "Web Apps" "$app_name - IP Restrictions" \
                "Pass" "IP restrictions configured: $ip_count rule(s)"
        fi
    else
        add_check_result "Web Apps" "$app_name - IP Restrictions" \
            "Info" "No IP restrictions configured" \
            "Consider adding IP restrictions for additional security"
    fi
    
    # Check for Key Vault references
    local app_settings
    app_settings=$(az webapp config appsettings list \
        --name "$app_name" \
        --resource-group "$app_rg" \
        2>/dev/null || echo "[]")
    
    local kv_ref_count
    kv_ref_count=$(echo "$app_settings" | jq '[.[] | select(.value | contains("@Microsoft.KeyVault"))] | length')
    
    if [[ "$kv_ref_count" -gt 0 ]]; then
        add_check_result "Web Apps" "$app_name - Key Vault Integration" \
            "Pass" "Using Key Vault references: $kv_ref_count setting(s)"
    else
        add_check_result "Web Apps" "$app_name - Key Vault Integration" \
            "Info" "No Key Vault references detected" \
            "Store secrets in Key Vault and reference them in app settings"
    fi
}

#===============================================================================
# Monitoring & Logging Checks
#===============================================================================

test_monitoring() {
    print_header "=== Monitoring & Logging Checks ==="
    
    # Check diagnostic settings
    local diag_settings
    diag_settings=$(az monitor diagnostic-settings list \
        --resource "$ASE_ID" \
        2>/dev/null || echo "{}")

    # Ensure .value is an array before indexing
    local diag_count
    diag_count=0
    if echo "$diag_settings" | jq -e '.value | type == "array"' >/dev/null 2>&1; then
        diag_count=$(echo "$diag_settings" | jq '.value | length')
    fi

    if [[ "$diag_count" -gt 0 ]]; then
        add_check_result "Monitoring" "Diagnostic Settings" \
            "Pass" "Diagnostic logging configured: $diag_count setting(s)"

        # Check for Log Analytics
        local la_count
        la_count=0
        if echo "$diag_settings" | jq -e '.value | type == "array"' >/dev/null 2>&1; then
            la_count=$(echo "$diag_settings" | jq '[.value[] | select(.workspaceId != null)] | length')
        fi

        if [[ "$la_count" -gt 0 ]]; then
            add_check_result "Monitoring" "Log Analytics Integration" \
                "Pass" "Logs sent to Log Analytics workspace"
        fi

        # Check for Storage Account
        local sa_count
        sa_count=0
        if echo "$diag_settings" | jq -e '.value | type == "array"' >/dev/null 2>&1; then
            sa_count=$(echo "$diag_settings" | jq '[.value[] | select(.storageAccountId != null)] | length')
        fi

        if [[ "$sa_count" -gt 0 ]]; then
            add_check_result "Monitoring" "Storage Account Archival" \
                "Pass" "Logs archived to Storage Account"
        fi
    else
        add_check_result "Monitoring" "Diagnostic Settings" \
            "Fail" "No diagnostic settings configured" \
            "Enable diagnostic logging to Log Analytics workspace"
    fi
    
    # Check for Security Center contacts
    local security_contacts
    security_contacts=$(az security contact list 2>/dev/null || echo "[]")
    
    local contact_count
    contact_count=$(echo "$security_contacts" | jq 'length')
    
    if [[ "$contact_count" -gt 0 ]]; then
        add_check_result "Monitoring" "Security Center Contacts" \
            "Pass" "Security contacts configured"
    else
        add_check_result "Monitoring" "Security Center Contacts" \
            "Warning" "No security contacts configured" \
            "Configure security contacts in Microsoft Defender for Cloud"
    fi
}

#===============================================================================
# Compliance & Governance Checks
#===============================================================================

test_compliance() {
    print_header "=== Compliance & Governance Checks ==="
    
    # Check for resource locks
    local locks
    locks=$(az lock list \
        --resource-group "$RESOURCE_GROUP" \
        2>/dev/null || echo "[]")
    
    local lock_count
    lock_count=$(echo "$locks" | jq 'length')
    
    if [[ "$lock_count" -gt 0 ]]; then
        add_check_result "Compliance" "Resource Locks" \
            "Pass" "Resource locks configured: $lock_count lock(s)"
    else
        add_check_result "Compliance" "Resource Locks" \
            "Warning" "No resource locks found" \
            "Apply CanNotDelete locks to production resources"
    fi
    
    # Check for tags
    local tags
    tags=$(echo "$ASE_JSON" | jq '.tags // {}')
    local tag_count
    tag_count=$(echo "$tags" | jq 'length')
    
    if [[ "$tag_count" -gt 0 ]]; then
        add_check_result "Compliance" "Resource Tagging" \
            "Pass" "Tags configured: $tag_count tag(s)"
    else
        add_check_result "Compliance" "Resource Tagging" \
            "Warning" "No tags configured" \
            "Add tags for cost tracking and governance (e.g., Environment, Owner, CostCenter)"
    fi
    
    # Check for Azure Policy assignments
    local subscription_id
    subscription_id=$(az account show --query "id" -o tsv)
    
    local policy_assignments
    policy_assignments=$(az policy assignment list \
        --scope "/subscriptions/$subscription_id/resourceGroups/$RESOURCE_GROUP" \
        2>/dev/null || echo "[]")
    
    local policy_count
    policy_count=$(echo "$policy_assignments" | jq 'length')
    
    if [[ "$policy_count" -gt 0 ]]; then
        add_check_result "Compliance" "Azure Policy" \
            "Pass" "Policy assignments found: $policy_count assignment(s)"
    else
        add_check_result "Compliance" "Azure Policy" \
            "Info" "No specific policy assignments at resource group level" \
            "Consider using Azure Policy to enforce security standards"
    fi
}

#===============================================================================
# HTML Report Generation
#===============================================================================

generate_html_report() {
    print_header "=== Generating Report ==="
    
    local compliance_percentage
    compliance_percentage=$(awk "BEGIN {printf \"%.2f\", ($SCORE / $TOTAL_CHECKS) * 100}")
    
    local ase_location
    local ase_kind
    ase_location=$(echo "$ASE_JSON" | jq -r '.location')
    ase_kind=$(echo "$ASE_JSON" | jq -r '.kind // "Not specified"')
    local report_date
    report_date=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Start HTML
    cat > "$OUTPUT_PATH" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>ASE Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; border-bottom: 2px solid #eee; padding-bottom: 5px; }
        h3 { color: #555; margin-top: 20px; }
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Azure ASE Security Assessment Report</h1>
        
        <div class="metadata">
EOF

    # Add metadata
    cat >> "$OUTPUT_PATH" << EOF
            <div class="metadata-item"><strong>ASE Name:</strong> $ASE_NAME</div>
            <div class="metadata-item"><strong>Resource Group:</strong> $RESOURCE_GROUP</div>
            <div class="metadata-item"><strong>Location:</strong> $ase_location</div>
            <div class="metadata-item"><strong>ASE Type:</strong> $ase_kind</div>
            <div class="metadata-item"><strong>Report Generated:</strong> $report_date</div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div style="text-align: center;">
                <div class="score">$compliance_percentage%</div>
                <div class="score-label">Security Compliance Score</div>
                <p style="margin-top: 15px;">$SCORE out of $TOTAL_CHECKS checks passed</p>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
EOF

    # Group results by category and generate tables
    local current_category=""
    
    for result in "${RESULTS[@]}"; do
        IFS='|' read -r category check status details recommendation <<< "$result"
        
        if [[ "$category" != "$current_category" ]]; then
            # Close previous table if exists
            if [[ -n "$current_category" ]]; then
                echo "                </tbody>" >> "$OUTPUT_PATH"
                echo "            </table>" >> "$OUTPUT_PATH"
                echo "        </div>" >> "$OUTPUT_PATH"
            fi
            
            # Start new category
            current_category="$category"
            cat >> "$OUTPUT_PATH" << EOF
        <div class="category-section">
            <h3>$category</h3>
            <table>
                <thead>
                    <tr>
                        <th>Check</th>
                        <th style="width: 100px;">Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
EOF
        fi
        
        # Add row
        local status_class
        status_class=$(echo "$status" | tr '[:upper:]' '[:lower:]')
        
        # Escape HTML entities
        details=$(echo "$details" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
        check=$(echo "$check" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
        recommendation=$(echo "$recommendation" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
        
        cat >> "$OUTPUT_PATH" << EOF
                    <tr>
                        <td><strong>$check</strong></td>
                        <td><span class="status $status_class">$status</span></td>
                        <td>
                            $details
EOF
        
        if [[ -n "$recommendation" ]]; then
            cat >> "$OUTPUT_PATH" << EOF
                            <div class="recommendation">💡 $recommendation</div>
EOF
        fi
        
        echo "                        </td>" >> "$OUTPUT_PATH"
        echo "                    </tr>" >> "$OUTPUT_PATH"
    done
    
    # Close last table
    if [[ -n "$current_category" ]]; then
        echo "                </tbody>" >> "$OUTPUT_PATH"
        echo "            </table>" >> "$OUTPUT_PATH"
        echo "        </div>" >> "$OUTPUT_PATH"
    fi
    
    # Calculate statistics
    local pass_count=0
    local fail_count=0
    local warn_count=0
    local info_count=0
    
    for result in "${RESULTS[@]}"; do
        IFS='|' read -r category check status details recommendation <<< "$result"
        case "$status" in
            "Pass") pass_count=$((pass_count + 1)) ;;
            "Fail") fail_count=$((fail_count + 1)) ;;
            "Warning") warn_count=$((warn_count + 1)) ;;
            "Info") info_count=$((info_count + 1)) ;;
        esac
    done
    
    # Add summary statistics and footer
    cat >> "$OUTPUT_PATH" << EOF
        <h2>Summary Statistics</h2>
        <table>
            <tr>
                <td><span class="status pass">Pass</span></td>
                <td>$pass_count</td>
            </tr>
            <tr>
                <td><span class="status fail">Fail</span></td>
                <td>$fail_count</td>
            </tr>
            <tr>
                <td><span class="status warning">Warning</span></td>
                <td>$warn_count</td>
            </tr>
            <tr>
                <td><span class="status info">Info</span></td>
                <td>$info_count</td>
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
EOF

    print_success "Report saved to: $OUTPUT_PATH"
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    # Parse command line arguments
    while getopts "g:n:o:dh" opt; do
        case $opt in
            g) RESOURCE_GROUP="$OPTARG" ;;
            n) ASE_NAME="$OPTARG" ;;
            o) OUTPUT_PATH="$OPTARG" ;;
            d) DEBUG=true ;;
            h) usage ;;
            \?) usage ;;
        esac
    done
    
    # Validate required parameters
    if [[ -z "$RESOURCE_GROUP" ]] || [[ -z "$ASE_NAME" ]]; then
        print_error "Error: Missing required parameters"
        usage
    fi
    
    # Print banner with version number
    SCRIPT_VERSION="v12.1"
    cat << EOF
╔═══════════════════════════════════════════════════════════════╗
║   Azure App Service Environment Security Assessment Script    ║
║                                                               ║
║   Version: $SCRIPT_VERSION                                    ║
║                                                               ║
║   This script validates your ASE configuration against        ║
║   security best practices for highly secure environments     ║
╚═══════════════════════════════════════════════════════════════╝

EOF
    
    # Check dependencies
    check_dependencies
    
    # Check Azure connection
    check_azure_login
    
    # Get ASE configuration
    get_ase_config
    
    # Run security checks
    test_network_isolation
    test_web_apps
    test_monitoring
    test_compliance
    
    # Generate HTML report
    generate_html_report
    
    # Display summary
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    ASSESSMENT COMPLETE                        ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    local compliance_percentage
    compliance_percentage=$(awk "BEGIN {printf \"%.2f\", ($SCORE / $TOTAL_CHECKS) * 100}")
    
    echo -n "Compliance Score: "
    if (( $(echo "$compliance_percentage >= 80" | bc -l) )); then
        print_success "$compliance_percentage% ✓"
    elif (( $(echo "$compliance_percentage >= 60" | bc -l) )); then
        print_warning "$compliance_percentage% ⚠"
    else
        print_error "$compliance_percentage% ✗"
    fi
    
    echo "Checks Passed: $SCORE / $TOTAL_CHECKS"
    echo ""
    print_success "HTML report generated: $OUTPUT_PATH"
    echo ""
    echo "Open the report in your browser for detailed findings and recommendations."
    echo ""
}

# Run main function
main "$@"
#===============================================================================
# End of Script v12.1
#===============================================================================
