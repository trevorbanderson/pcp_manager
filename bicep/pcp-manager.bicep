// PCP Manager – Azure Container App
// Deploys the Flask web app with:
//   • System-assigned managed identity (used to pull secrets from Key Vault)
//   • Key Vault Secrets User RBAC role assignment for that identity
//   • Ingress on port 5000 (Flask default)
//   • Environment variables sourced from .env [STAGING] / [PROD] sections
//   • Log output forwarded to the Container Apps Environment (Azure Monitor)

param location string = 'East US 2'

@description('Container Apps managed environment name (created by pcp_iac)')
param envName string = 'pcp-containers'

@description('Name of this container app')
param appName string = 'pcp-manager'

@description('Target environment (staging | prod)')
@allowed(['staging', 'prod'])
param environment string = 'staging'

@description('ACR image tag to deploy')
param imageTag string = 'latest'

@description('ACR registry password secret')
@secure()
param registryPassword string

@description('Key Vault name – used to grant secrets read access')
param keyVaultName string = 'AKV-AgileInnovations-Dev'

@description('PostgreSQL host (FQDN of the flexible server)')
param dbHost string = 'pcpdb.postgres.database.azure.com'

@description('PostgreSQL database name')
param dbName string = 'pcp'

@description('PostgreSQL user')
param dbUser string = 'pgadmin'

@description('Build/version identifier (injected by pipeline as Build.BuildId)')
param appVersion string = 'local'

@description('SMTP username for outbound mail')
param mailUsername string = 'patterncopilot@gmail.com'

@description('Log directory on the container file system')
param logDir string = '/var/log/pcp_manager'

// ── References to shared infrastructure (deployed by pcp_iac) ────────────
resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' existing = {
  name: envName
}

// ── Container App ─────────────────────────────────────────────────────────
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: appName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 5000
        transport: 'Auto'
        traffic: [
          {
            weight: 100
            latestRevision: true
          }
        ]
      }
      registries: [
        {
          server: 'agileinnovations.azurecr.io'
          username: 'AgileInnovations'
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        {
          name: 'acr-password'
          value: registryPassword
        }
      ]
    }
    template: {
      containers: [
        {
          name: appName
          image: 'agileinnovations.azurecr.io/pcp-manager:${imageTag}'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'ENVIRONMENT',          value: environment }
            { name: 'USE_MANAGED_IDENTITY', value: 'true' }
            { name: 'AZURE_KEY_VAULT_URL',  value: 'https://${keyVaultName}${az.environment().suffixes.keyvaultDns}/' }
            { name: 'DB_HOST',              value: dbHost }
            { name: 'DB_PORT',              value: '5432' }
            { name: 'DB_NAME',              value: dbName }
            { name: 'DB_USER',              value: dbUser }
            { name: 'DB_SSLMODE',           value: 'require' }
            { name: 'APP_VERSION',          value: appVersion }
            { name: 'LOG_DIR',              value: logDir }
            { name: 'MAIL_SERVER',          value: 'smtp.gmail.com' }
            { name: 'MAIL_PORT',            value: '587' }
            { name: 'MAIL_USE_TLS',         value: 'true' }
            { name: 'MAIL_USERNAME',        value: mailUsername }
            { name: 'MAIL_DEFAULT_SENDER',  value: mailUsername }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '20'
              }
            }
          }
        ]
      }
    }
  }
}

// ── Outputs ───────────────────────────────────────────────────────────────
// Note: Key Vault Secrets User role assignment is handled by the pipeline
// (az role assignment create) so the deployment SP needs no roleAssignments/write.
output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output managedIdentityPrincipalId string = containerApp.identity.principalId
