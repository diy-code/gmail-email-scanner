## deploy.ps1 — Full Cloud Run deployment with hard $1 spending kill switch
## Run this ONCE after billing is enabled on email-scanner-yb151

$env:PATH = "C:\Users\yb151\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin;" + $env:PATH

$PROJECT   = "email-scanner-yb151"
$REGION    = "us-central1"
$SERVICE   = "email-scanner-backend"
$IMAGE     = "gcr.io/$PROJECT/$SERVICE"

# --------------------------------------------------------------------------
# Load API keys from backend/.env
# --------------------------------------------------------------------------
$envFile = "$PSScriptRoot\backend\.env"
$envVars = @{}
Get-Content $envFile | ForEach-Object {
    if ($_ -match "^\s*([^#][^=]+)=(.+)$") {
        $envVars[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$VT_KEY   = $envVars["VIRUSTOTAL_API_KEY"]
$AB_KEY   = $envVars["ABUSEIPDB_API_KEY"]
$SB_KEY   = $envVars["SAFE_BROWSING_API_KEY"]
$OA_KEY   = $envVars["OPENAI_API_KEY"]
$API_KEY  = $envVars["API_KEY"]

Write-Host "`n=== Step 1: Set project ===" -ForegroundColor Cyan
gcloud config set project $PROJECT
gcloud config set run/region $REGION

# --------------------------------------------------------------------------
# Step 2: Enable required APIs
# --------------------------------------------------------------------------
Write-Host "`n=== Step 2: Enable APIs ===" -ForegroundColor Cyan
gcloud services enable `
    run.googleapis.com `
    cloudbuild.googleapis.com `
    containerregistry.googleapis.com `
    billingbudgets.googleapis.com `
    pubsub.googleapis.com `
    cloudfunctions.googleapis.com `
    --project $PROJECT

# --------------------------------------------------------------------------
# Step 3: Build and push Docker image via Cloud Build
# --------------------------------------------------------------------------
Write-Host "`n=== Step 3: Build Docker image ===" -ForegroundColor Cyan
Set-Location "$PSScriptRoot\backend"
gcloud builds submit --tag $IMAGE --project $PROJECT

# --------------------------------------------------------------------------
# Step 4: Deploy to Cloud Run
#   --max-instances=1  → hard cap: only 1 container ever runs (free tier safe)
#   --min-instances=0  → scale to zero when idle (no idle charges)
#   --memory=512Mi     → minimal memory footprint
#   --cpu=1            → 1 vCPU, allocated only during requests
#   --timeout=60       → max 60s per request
#   --concurrency=10   → max 10 concurrent requests per instance
# --------------------------------------------------------------------------
Write-Host "`n=== Step 4: Deploy to Cloud Run ===" -ForegroundColor Cyan
gcloud run deploy $SERVICE `
    --image $IMAGE `
    --platform managed `
    --region $REGION `
    --allow-unauthenticated `
    --max-instances 1 `
    --min-instances 0 `
    --memory 512Mi `
    --cpu 1 `
    --timeout 60 `
    --concurrency 10 `
    --set-env-vars "VIRUSTOTAL_API_KEY=$VT_KEY,ABUSEIPDB_API_KEY=$AB_KEY,SAFE_BROWSING_API_KEY=$SB_KEY,OPENAI_API_KEY=$OA_KEY,API_KEY=$API_KEY" `
    --project $PROJECT

# --------------------------------------------------------------------------
# Step 5: Get the deployed URL
# --------------------------------------------------------------------------
Write-Host "`n=== Step 5: Get service URL ===" -ForegroundColor Cyan
$SERVICE_URL = gcloud run services describe $SERVICE `
    --region $REGION --format "value(status.url)" --project $PROJECT
Write-Host "Backend URL: $SERVICE_URL" -ForegroundColor Green

# --------------------------------------------------------------------------
# Step 6: Set up billing kill switch
#   Creates a $1 budget. At 100% threshold it sends a Pub/Sub message
#   to a Cloud Function that calls `gcloud billing projects unlink` —
#   this DISABLES BILLING on the project entirely, stopping all services.
# --------------------------------------------------------------------------
Write-Host "`n=== Step 6: Billing kill switch ===" -ForegroundColor Cyan

# Get billing account ID
$BILLING_ACCOUNT = gcloud billing projects describe $PROJECT `
    --format "value(billingAccountName)" | Split-Path -Leaf
Write-Host "Billing account: $BILLING_ACCOUNT"

# Create Pub/Sub topic that the budget will notify
gcloud pubsub topics create billing-alert --project $PROJECT

# Create the kill-switch Cloud Function source
$funcDir = "$env:TEMP\billing_kill"
New-Item -ItemType Directory -Force -Path $funcDir | Out-Null

@'
const {CloudBillingClient} = require('@google-cloud/billing');
const billing = new CloudBillingClient();

exports.killBilling = async (pubsubEvent) => {
    const data = JSON.parse(Buffer.from(pubsubEvent.data, 'base64').toString());
    // Only kill if we have hit or exceeded 100% of budget
    if (data.costAmount >= data.budgetAmount) {
        const projectName = `projects/` + process.env.PROJECT_ID;
        console.log(`Cost $${data.costAmount} >= budget $${data.budgetAmount}. Disabling billing.`);
        await billing.updateProjectBillingInfo({
            name: projectName,
            projectBillingInfo: { billingAccountName: '' }  // empty = unlink billing
        });
        console.log('Billing disabled.');
    } else {
        console.log(`Cost $${data.costAmount} — within budget. No action.`);
    }
};
'@ | Set-Content "$funcDir\index.js"

@'
{
  "name": "billing-kill-switch",
  "version": "1.0.0",
  "dependencies": {
    "@google-cloud/billing": "^4.0.0"
  }
}
'@ | Set-Content "$funcDir\package.json"

# Grant the Cloud Function's service account permission to unlink billing
$PROJECT_NUMBER = gcloud projects describe $PROJECT --format "value(projectNumber)"
$SA = "$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
gcloud projects add-iam-policy-binding $PROJECT `
    --member "serviceAccount:$SA" `
    --role "roles/billing.projectManager"

# Deploy the kill-switch function
gcloud functions deploy billing-kill-switch `
    --region $REGION `
    --runtime nodejs20 `
    --trigger-topic billing-alert `
    --entry-point killBilling `
    --set-env-vars "PROJECT_ID=$PROJECT" `
    --source $funcDir `
    --project $PROJECT

# Create the budget: $1 limit, alerts at 50c and $1, kill at $1
gcloud billing budgets create `
    --billing-account $BILLING_ACCOUNT `
    --display-name "Email Scanner Hard Cap" `
    --budget-amount 1USD `
    --threshold-rule percent=50,basis=CURRENT_SPEND `
    --threshold-rule percent=90,basis=CURRENT_SPEND `
    --threshold-rule percent=100,basis=CURRENT_SPEND `
    --notifications-rule pubsub-topic="projects/$PROJECT/topics/billing-alert",schema-version=1.0

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "Backend URL : $SERVICE_URL" -ForegroundColor Green
Write-Host 'Budget      : Hard cap at $1 — billing auto-disabled if exceeded' -ForegroundColor Green
Write-Host ""
Write-Host "=== Step 7: Update addon Script Properties ===" -ForegroundColor Cyan
Write-Host 'Run the following in the Apps Script editor (Code.gs -> setup()):'
Write-Host "  BACKEND_URL  = $SERVICE_URL" -ForegroundColor Yellow
Write-Host "  BACKEND_API_KEY = $API_KEY" -ForegroundColor Yellow

# --------------------------------------------------------------------------
# Step 7: Auto-update the addon setup() function with the real URL
# --------------------------------------------------------------------------
Set-Location "$PSScriptRoot\addon"
$codeGs = Get-Content "$PSScriptRoot\addon\Code.gs" -Raw
$codeGs = $codeGs -replace "https://REPLACE_WITH_YOUR_CLOUD_RUN_URL", $SERVICE_URL
Set-Content "$PSScriptRoot\addon\Code.gs" $codeGs
clasp push --force
Write-Host "Addon Code.gs updated and pushed with real backend URL." -ForegroundColor Green
Write-Host ""
Write-Host 'NEXT: Open Apps Script editor and run setup() once:' -ForegroundColor Cyan
Write-Host '  https://script.google.com/d/1nzC93ElbxcXP9RFkkhuczYeEvxRIpBsOkbCgLbogOGZJz4hlJGudb64H/edit'
