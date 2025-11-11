#!/bin/bash

# Azure App Service Environment Health Check Script
# This script validates that your ASE is ready to host applications

set -e  # Exit on error

# Configuration
ASE_NAME=""        # Set this to the name of your ASE
RESOURCE_GROUP=""  # Set this to your resource group name

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" == "OK" ]; then
        echo -e "${GREEN}✓${NC} $message"
    elif [ "$status" == "WARN" ]; then
        echo -e "${YELLOW}⚠${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
    fi
}

echo "================================================"
echo "ASE Health Check for: $ASE_NAME"
echo "================================================"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_status "ERROR" "Azure CLI is not installed"
    exit 1
fi
print_status "OK" "Azure CLI is installed"

# Check if logged in
if ! az account show &> /dev/null; then
    print_status "ERROR" "Not logged in to Azure. Run 'az login' first"
    exit 1
fi
print_status "OK" "Logged in to Azure"

# Get current subscription
SUBSCRIPTION=$(az account show --query name -o tsv)
echo -e "Using subscription: ${YELLOW}$SUBSCRIPTION${NC}"
echo ""

# If resource group not set, try to find it
if [ -z "$RESOURCE_GROUP" ]; then
    echo "Searching for ASE '$ASE_NAME'..."
    RESOURCE_GROUP=$(az appservice ase list --query "[?name=='$ASE_NAME'].resourceGroup | [0]" -o tsv)
    
    if [ -z "$RESOURCE_GROUP" ]; then
        print_status "ERROR" "Could not find ASE '$ASE_NAME' or RESOURCE_GROUP not set"
        exit 1
    fi
    echo -e "Found ASE in resource group: ${YELLOW}$RESOURCE_GROUP${NC}"
    echo ""
fi

# Test 1: Check if ASE exists
echo "Test 1: Checking if ASE exists..."
ASE_EXISTS=$(az appservice ase show --name "$ASE_NAME" --resource-group "$RESOURCE_GROUP" 2>/dev/null)
if [ -z "$ASE_EXISTS" ]; then
    print_status "ERROR" "ASE '$ASE_NAME' not found in resource group '$RESOURCE_GROUP'"
    exit 1
fi
print_status "OK" "ASE exists"
echo ""

# Test 2: Check ASE provisioning state
echo "Test 2: Checking ASE provisioning state..."
PROVISIONING_STATE=$(az appservice ase show --name "$ASE_NAME" --resource-group "$RESOURCE_GROUP" --query provisioningState -o tsv)
if [ "$PROVISIONING_STATE" == "Succeeded" ]; then
    print_status "OK" "Provisioning state: $PROVISIONING_STATE"
else
    print_status "WARN" "Provisioning state: $PROVISIONING_STATE (Expected: Succeeded)"
fi
echo ""

# Test 3: Check ASE status
echo "Test 3: Checking ASE status..."
STATUS=$(az appservice ase show --name "$ASE_NAME" --resource-group "$RESOURCE_GROUP" --query status -o tsv)
if [ "$STATUS" == "Ready" ]; then
    print_status "OK" "ASE status: $STATUS"
else
    print_status "WARN" "ASE status: $STATUS (Expected: Ready)"
fi
echo ""

# Test 4: Get ASE details
echo "Test 4: Retrieving ASE configuration..."
ASE_INFO=$(az appservice ase show --name "$ASE_NAME" --resource-group "$RESOURCE_GROUP" -o json)

LOCATION=$(echo "$ASE_INFO" | jq -r '.location')
KIND=$(echo "$ASE_INFO" | jq -r '.kind')
INTERNAL_LOAD_BALANCING=$(echo "$ASE_INFO" | jq -r '.internalLoadBalancingMode')
DNS_SUFFIX=$(echo "$ASE_INFO" | jq -r '.dnsSuffix')

echo "  Location: $LOCATION"
echo "  Kind: $KIND"
echo "  Load Balancing Mode: $INTERNAL_LOAD_BALANCING"
echo "  DNS Suffix: $DNS_SUFFIX"
print_status "OK" "ASE configuration retrieved"
echo ""

# Test 5: Check VNet integration
echo "Test 5: Checking VNet integration..."
VNET_ID=$(echo "$ASE_INFO" | jq -r '.virtualNetwork.id')
if [ ! -z "$VNET_ID" ] && [ "$VNET_ID" != "null" ]; then
    VNET_NAME=$(echo "$VNET_ID" | awk -F'/' '{print $(NF)}')
    print_status "OK" "VNet configured: $VNET_NAME"
else
    print_status "WARN" "No VNet configuration found"
fi
echo ""

# Test 6: Check available worker pools
echo "Test 6: Checking worker pools..."
WORKER_POOLS=$(az appservice ase list-plans --name "$ASE_NAME" --resource-group "$RESOURCE_GROUP" 2>/dev/null || echo "[]")
WORKER_COUNT=$(echo "$WORKER_POOLS" | jq '. | length')

if [ "$WORKER_COUNT" -gt 0 ]; then
    print_status "OK" "Found $WORKER_COUNT App Service Plan(s) in ASE"
    echo "$WORKER_POOLS" | jq -r '.[] | "  - \(.name) (\(.sku.name))"'
else
    print_status "WARN" "No App Service Plans found (you'll need to create one to host apps)"
fi
echo ""

# Test 7: Check existing apps
echo "Test 7: Checking for existing applications..."
APPS=$(az webapp list --resource-group "$RESOURCE_GROUP" --query "[?hostingEnvironmentProfile.name=='$ASE_NAME']" -o json)
APP_COUNT=$(echo "$APPS" | jq '. | length')

if [ "$APP_COUNT" -gt 0 ]; then
    print_status "OK" "Found $APP_COUNT application(s) hosted in ASE"
    echo "$APPS" | jq -r '.[] | "  - \(.name) (State: \(.state))"'
else
    print_status "OK" "No applications currently hosted (ASE is ready for deployment)"
fi
echo ""

# Test 8: Network connectivity test (if possible)
echo "Test 8: Checking DNS suffix accessibility..."
if [ ! -z "$DNS_SUFFIX" ] && [ "$DNS_SUFFIX" != "null" ]; then
    print_status "OK" "DNS suffix configured: $DNS_SUFFIX"
    echo "  Note: Test actual connectivity to *.${DNS_SUFFIX} from your network"
else
    print_status "WARN" "No custom DNS suffix configured"
fi
echo ""

# Summary
echo "================================================"
echo "SUMMARY"
echo "================================================"
echo ""

if [ "$PROVISIONING_STATE" == "Succeeded" ] && [ "$STATUS" == "Ready" ]; then
    print_status "OK" "ASE '$ASE_NAME' is READY to host applications"
    echo ""
    echo "Next steps:"
    echo "  1. Create an App Service Plan in this ASE (if not already created)"
    echo "  2. Deploy your applications to the ASE"
    echo ""
    echo "Example: Create an App Service Plan"
    echo "  az appservice plan create \\"
    echo "    --name <plan-name> \\"
    echo "    --resource-group $RESOURCE_GROUP \\"
    echo "    --app-service-environment $ASE_NAME \\"
    echo "    --sku I1v2"
    exit 0
else
    print_status "WARN" "ASE may not be fully ready"
    echo "  Provisioning State: $PROVISIONING_STATE"
    echo "  Status: $STATUS"
    exit 1
fi
