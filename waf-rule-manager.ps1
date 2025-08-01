#!/usr/bin/pwsh


$testIPs = @()

function isValidIP($ip) {
    return $ip -match '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
}

function readIPsFromCsv($filePath) {
    if (-not (Test-Path $filePath)) {
        Write-Host "File not found: $filePath"
        return @()
    }

    $ips = @()
    try {
        $csvContent = Import-Csv -Path $filePath
        foreach ($row in $csvContent) {
            if (-not [string]::IsNullOrEmpty($row.IP) -and (isValidIP($row.IP))) {
                $ips += $row.IP
            } else {
                Write-Host "Invalid IP found in CSV: $($row.IP)"
            }
        }
    } catch {
        Write-Host "Error reading CSV file: $_"
    }
    return $ips
}

# # optional dowload JSON of IPs from feed
# $testIPs = (irm "https://quic.cloud/ips?json") 
# # Write-Host "Test IPs: $testIPs"


function matchConditionFromIPArray($ips) {
    # {"type":"condition","op":"in","key":"sourceIdentifier","value":["1.1.1.1","8.8.8.8","8.8.4.4"]}
    $condition = @{
        "type" = "condition";
        "op" = "in";
        "key" = "sourceIdentifier";
        "value" = $ips
    }
    return $condition | ConvertTo-Json -Depth 10 -Compress
}

# $whitelistedIps =  @(
#     "1.1.1.1",
#     "8.8.8.8",
#     "8.8.4.4",
#     "169.254.0.1",
#     "169.254.0.2", "169.254.0.3"
# ) + (irm "https://quic.cloud/ips?json") 
# $whitelistedIps += $testIPs

$whitelistedIps = readIPsFromCsv "data/whitelist.csv"

$whitelistedIps2 = @(
    "1.1.1.1",
    "8.8.8.8",
    "8.8.4.4"
) 

$blockedIps = readIPsFromCsv "data/blacklist.csv"
# $blockedIps =  @(
#     "8.8.4.4",
#     "8.8.8.8",
#     "100.100.1.1",
#     "100.100.1.2", "100.100.1.3", "100.100.1.4"
# )






$ruleUpdates = @(
    @{
        "updateTag" = "BLOCK_LIST1";
        "fields" = @{
             "match" = matchConditionFromIPArray $blockedIps
        }
    }
    @{
        "updateTag" = "WHITE_LIST1";
        "fields"= @{
             "match" = matchConditionFromIPArray $whitelistedIps
        }
    }  
        @{
        "updateTag" = "WHITE_LIST2";
        "fields"= @{
             "match" = matchConditionFromIPArray $whitelistedIps2
        }
    }  
)

# current script name
$scriptName = $MyInvocation.MyCommand.Name
Write-Host "Script Name: $scriptName"

# Write-Host "${env:WAF_API_KEY} ${env:WAF_API_KEY_SECRET}"

# must have a WAF_API_KEY and WAF_API_KEY_SECRET environment variable set
if (-not $env:WAF_API_KEY -or -not $env:WAF_API_KEY_SECRET) {
    Write-Host "WAF_API_KEY and WAF_API_KEY_SECRET environment variables must be set."
    exit 1
}

function login {
    $apiKey = $env:WAF_API_KEY
    $apiKeySecret = $env:WAF_API_KEY_SECRET
    $loginUrl = "https://cloudinfra-gw.portal.checkpoint.com/auth/external"

    # {"clientId":"{{apiKey}}","accessKey":"{{apiKeySecret}}"}
    $body = @{
        "clientId" = $apiKey;
        "accessKey" = $apiKeySecret;
    } | ConvertTo-Json
    $headers = @{
        "Content-Type" = "application/json";
    }
    $response = Invoke-RestMethod -Uri $loginUrl -Method Post -Headers $headers -Body $body
    if ($response -and $response.success) {
        Write-Host "Login successful. Token received."
        return $response.data.token
    } else {
        Write-Host "Login failed. No token received."
        exit 1
    }
    return $null
}

function addWhitelistRulebase($token, $ips, $assetId) {

    Write-Host "Adding whitelist rulebase for asset ID: $assetId with IPs: $($ips -join ', ')"

     $bodyTemplate = @'
{
  "operationName": "newExceptionParameter",
  "variables": {
    "ownerId": "32cc2afb-232a-4979-decb-07932874dced",
    "parameterInput": {
      "exceptions": [
        {
          "match": "{\"type\":\"condition\",\"op\":\"equals\",\"key\":\"countryCode\",\"value\":[\"AD\"]}",
          "actions": [
            "{\"key\":\"action\",\"value\":\"accept\"}"
          ],
          "comment": "WHITE_LIST1",
          "supportedPracticesTypes": []
        }
      ]
    }
  },
  "query": "mutation newExceptionParameter($ownerId: ID, $practiceId: ID, $parameterInput: ExceptionParameterInput) {\n  newExceptionParameter(\n    ownerId: $ownerId\n    practiceId: $practiceId\n    parameterInput: $parameterInput\n  ) {\n    id\n    __typename\n  }\n}\n"
}
'@

    $body = $bodyTemplate | ConvertFrom-Json
    $body.variables.ownerId = $assetId
    
        # $exception = @{
        #     "match" = matchConditionFromIPArray $ips
        #     "actions" = @(@{"key" = "action"; "value" = "skip"})
        #     "comment" = "WHITE_LIST1"
        # }
    $body.variables.parameterInput.exceptions[0].match = matchConditionFromIPArray $ips
    

    # Write-Host "Calling" ($body | ConvertTo-Json -Depth 10)

    $url = 'https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql' 
    $headers = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $($token)"
    }

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 10)

    # Write-Host "Response: $($response | ConvertTo-Json -Depth 10)"
    if ($response -and $response.data -and $response.data.newExceptionParameter) {
        Write-Host "Whitelist rulebase created successfully."
        return $response.data.newExceptionParameter
    } else {
        Write-Host "Failed to create whitelist rulebase."
        Write-Host "Response: $($response | ConvertTo-Json -Depth 10)"
        return $null
    }
}

function getApiAssets($token) {
    $body = @'
{
  "operationName": "AssetsName",
  "variables": {
     "matchSearch": [
        ""
     ],
     "globalObject": false,
     "paging": {
        "offset": 0,
        "limit": 50
     },
     "filters": {}
  },
  "query": "query AssetsName($matchSearch: [String], $sortBy: SortBy, $globalObject: Boolean, $filters: AssetsFilter, $paging: Paging) {\n  getAssets(\n    matchSearch: $matchSearch\n    sortBy: $sortBy\n    globalObject: $globalObject\n    filters: $filters\n    paging: $paging\n  ) {\n    assets {\n      id\n      name\n      assetType\n      __typename\n    }\n    __typename\n  }\n}\n"
}
'@

    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql"
    $headers = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $($token)"
    }

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    if ($response -and $response.data -and $response.data.getAssets) {
        
        Write-Host "Assets retrieved successfully."
        Write-Host "Total Assets: $($response.data.getAssets.assets.Count)"

        $assets = $response.data.getAssets.assets
        foreach ($asset in $assets) {
            Write-Host "Asset ID: $($asset.id), Name: $($asset.name), Type: $($asset.assetType)"
        }
        return $assets
    } else {
        Write-Host "Failed to retrieve assets or no assets found."
        exit 1
    }

   # Write-Host $body
}

function getAsset($token, $assetId) {
    $body = @'
{
  "operationName": "GetAssetQuery",
  "variables": {
    "assetId": "7acbd32e-03dc-e86c-0323-4c7604b431e3"
  },
  "query": "query Asset($id: String!, $sourceIds: [String!]) {\n  getAsset(id: $id, sourceIds: $sourceIds) {\n    __typename\n    id\n    name\n    objectStatus\n    status\n    mainPracticeMode\n    assetType\n    family\n    category\n    class\n    order\n    kind\n    group\n    readOnly\n    sources\n    mainAttributes\n    intelligenceTags\n    state\n    refId\n    parentZone {\n      id\n      name\n      subType\n      __typename\n    }\n    triggers {\n      id\n      name\n      triggerType\n      __typename\n    }\n    practices {\n      id\n      priority {\n        id\n        name\n        __typename\n      }\n      practice {\n        id\n        name\n        practiceType\n        visibility\n        category\n        __typename\n      }\n      modes {\n        mode\n        subPractice\n        __typename\n      }\n      practiceScope {\n        scope\n        inheritedFrom {\n          id\n          name\n          __typename\n        }\n        __typename\n      }\n      triggers {\n        id\n        name\n        triggerType\n        __typename\n      }\n      priority {\n        id\n        name\n        __typename\n      }\n      parameters {\n        id\n        name\n        parameterType\n        visibility\n        ... on ExceptionParameter {\n          id\n          usedByNames\n          exceptions {\n            id\n            match\n            actions {\n              id\n              action\n              __typename\n            }\n            comment\n            metadata {\n              objectStatus\n              time\n              by\n              __typename\n            }\n            supportedPracticesTypes {\n              id\n              practiceType\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    parameters {\n      id\n      name\n      type\n      subType\n      __typename\n    }\n    behaviors {\n      id\n      parameterType\n      id\n      name\n      parameterType\n      visibility\n      ... on ExceptionParameter {\n        id\n        usedByNames\n        exceptions {\n          id\n          match\n          actions {\n            id\n            action\n            __typename\n          }\n          comment\n          metadata {\n            objectStatus\n            time\n            by\n            __typename\n          }\n          supportedPracticesTypes {\n            id\n            practiceType\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    profiles {\n      id\n      name\n      profileType\n      ... on KubernetesProfile {\n        profileManagedBy\n        __typename\n      }\n      ... on EmbeddedProfile {\n        profileManagedBy\n        __typename\n      }\n      ... on DockerProfile {\n        profileManagedBy\n        __typename\n      }\n      __typename\n    }\n    tags {\n      id\n      tag\n      __typename\n    }\n    ... on GenericAsset {\n      URLs {\n        id\n        URL\n        __typename\n      }\n      stage\n      __typename\n    }\n    ... on GenericIotAsset {\n      URLs {\n        id\n        URL\n        __typename\n      }\n      stage\n      __typename\n    }\n    ... on WebApplicationAsset {\n      createdAt\n      lastChange {\n        timestamp\n        by\n        __typename\n      }\n      URLs {\n        id\n        URL\n        __typename\n      }\n      uri\n      prompt\n      __typename\n    }\n    ... on IoTDeviceAsset {\n      displayName\n      iotCategory\n      function\n      manufacturer\n      model\n      ipv4Addresses {\n        id\n        ipv4\n        __typename\n      }\n      macAddresses {\n        id\n        mac\n        __typename\n      }\n      riskLevel\n      vlan\n      recognitionConfidence\n      rawData {\n        resetCounter\n        __typename\n      }\n      __typename\n    }\n  }\n}\n"
}
'@
    $query = @'

    query GetAssetQuery($assetId: String!) {
  getAsset(id: $assetId) {
   tags { tag id }
   id name
    behaviors {
      id
      parameterType
      id
      name
      parameterType
      visibility
      ... on ExceptionParameter {
        id
        usedByNames
        exceptions {
          id
          match
          actions {
            id
            action
            __typename
          }
          comment
          metadata {
            objectStatus
            time
            by
            __typename
          }
          supportedPracticesTypes {
            id
            practiceType
            __typename
          }
          __typename
        }
        __typename
      }
      __typename
    }
  }
}
'@

    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql"
    $headers = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $($token)"
    }
    $bodyData = $body | ConvertFrom-Json
    $bodyData.variables.assetId = $assetId
    $bodyData.query = $query
    $body = $bodyData | ConvertTo-Json -Depth 10

    # Write-Host "Retrieving asset with ID: $assetId"
    # Write-Host "Request Body: $body"

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    if ($response -and $response.data -and $response.data.getAsset) {
        # Write-Host "Asset retrieved successfully."
        $asset = $response.data.getAsset
        # Write-Host "Asset ID: $($asset.id), Name: $($asset.name), Type: $($asset.assetType)"
        # Write-Host "Asset Details: $($asset | ConvertTo-Json -Depth 10)"
        return $asset
    } else {
        Write-Host "Failed to retrieve asset or no asset found."
        exit 1
    }
}


function addExceptionRule($token, $ips, $exceptionRulebaseId, $prevRuleId) {
    Write-Host "Adding exception rule for asset ID: $assetId with IPs: $($ips -join ', ')"

    $bodyTemplate = @'
{
  "operationName": "addExceptionExceptionsObject",
  "variables": {
    "id": "02cc324f-dd5f-4300-039d-c630dec0fa47",
    "previousObjectId": "c4cc324f-dd9e-b8b4-11e4-0c66c270e32e",
    "addObject": {
      "match": "{\"type\":\"condition\",\"op\":\"equals\",\"key\":\"countryCode\",\"value\":[\"AD\"]}",
      "actions": [
        "{\"key\":\"action\",\"value\":\"accept\"}"
      ],
      "comment": "WHITE_LIST1",
      "supportedPracticesTypes": []
    }
  },
  "query": "mutation addExceptionExceptionsObject($addObject: ExceptionObjectInput, $id: ID, $previousObjectId: ID) {\n  addExceptionExceptionsObject(\n    addObject: $addObject\n    id: $id\n    previousObjectId: $previousObjectId\n  ) {\n    id\n    match\n    comment\n    actions {\n      id\n      action\n      __typename\n    }\n    supportedPracticesTypes {\n      id\n      practiceType\n      __typename\n    }\n    __typename\n  }\n}\n"
}
'@

$body = $bodyTemplate | ConvertFrom-Json
    $body.variables.id = $exceptionRulebaseId
    $body.variables.previousObjectId = $null #$prevRuleId
    $body.variables.addObject.match = matchConditionFromIPArray $ips

    # Write-Host "Calling" ($body | ConvertTo-Json -Depth 10)

    $url = 'https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql' 
    $headers = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $($token)"
    }
    $body = $body | ConvertTo-Json -Depth 10
    # Write-Host "Request Body: $body"
    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    Write-Host "Response: $($response | ConvertTo-Json -Depth 10)"

}

function updateException($token, $behaviorId, $exceptionId, $updateFields, $currentException) {
    Write-Host "    Updating exception ID: $exceptionId in behavior ID: $behaviorId "
    # with fields: $($updateFields | ConvertTo-Json -Depth 10)"

    # Write-Host "Current Exception: $($currentException | ConvertTo-Json -Depth 10)"

    # iterate updateFields and update the currentException
    # foreach ($key in $updateFields.Keys) {
    #     if ($currentException.PSObject.Properties[$key]) {
    #         Write-Host "Updating field '$key' from '$($currentException.$key)' to '$($updateFields[$key])'"
    #         $currentException.$key = $updateFields[$key]
    #     }
    # }

    $query = @'
mutation updateExceptionParameter($id: ID!, $parameterInput: ExceptionParameterUpdateInput) 
{  
  updateExceptionParameter(id: $id, parameterInput: $parameterInput)
}
'@

    $variablesJson = @'
{
    "id": "1ecc18a9-f603-6447-1ce5-4b938112483f",
    "parameterInput": {
      "updateExceptions": [
        {
          "id": "72cc18a9-f674-daf0-c2b4-6a5a9d69758a",
          "match": "{\"type\":\"operator\",\"op\":\"or\",\"items\":[{\"type\":\"condition\",\"op\":\"equals\",\"key\":\"countryName\",\"value\":[\"Germany\"]},{\"type\":\"condition\",\"op\":\"equals\",\"key\":\"countryName\",\"value\":[\"Slovakia\"],\"disableOps\":[]},{\"type\":\"condition\",\"op\":\"in\",\"key\":\"sourceIdentifier\",\"value\":[\"1.1.1.1\",\"8.8.4.4\",\"8.8.8.8\"],\"disableOps\":[]}]}",
          "updateActions": [
            {
              "id": "d6cc1e25-4d8b-b18d-18c4-1ab0a686a42c",
              "action": "{\"key\":\"action\",\"value\":\"skip\"}"
            }
          ],
          "addSupportedPracticesTypes": [],
          "removeSupportedPracticesTypes": [],
          "comment": "geo and IP list to whitelist traffic 47 in cz rule"
        }
      ]
    }
}
'@
    $variables = $variablesJson | ConvertFrom-Json

    $variables.id = $behaviorId
    $variables.parameterInput.updateExceptions[0].id = $exceptionId
    $variables.parameterInput.updateExceptions[0].match = $updateFields.match
    $variables.parameterInput.updateExceptions[0].updateActions = @()
    $variables.parameterInput.updateExceptions[0].comment = $currentException.comment

    $body = @{
        "operationName" = "updateExceptionParameter";
        "variables" = $variables;
        "query" = $query
    } | ConvertTo-Json -Depth 10

    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql"
    $headers = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $($token)"
    }

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    # Write-Host "Response: $($response | ConvertTo-Json -Depth 10)"
    if ($response -and $response.data -and $response.data.updateExceptionParameter) {
        Write-Host "    Exception updated successfully."
        $updateResult = $response.data.updateExceptionParameter
        # Write-Host "Update Result: $updateResult"
        return $true
    } else {
        Write-Host "Failed to update exception."
        if ($response.errors) {
            Write-Host "Errors:"
            foreach ($error in $response.errors) {
                Write-Host " - $($error.message)"
            }
        }
    }
}

function publish($token) {
    $body = @'
{
  "operationName": "publishChanges",
  "variables": {
    "profileTypes": [
      "Docker",
      "CloudGuardAppSecGateway",
      "Embedded",
      "Kubernetes",
      "AppSecSaaS"
    ]
  },
  "query": "mutation publishChanges($profileTypes: [ProfileType!], $skipNginxValidation: Boolean) {\n  publishChanges(\n    profileTypes: $profileTypes\n    skipNginxValidation: $skipNginxValidation\n  ) {\n    isValid\n    errors {\n      message\n      __typename\n    }\n    warnings {\n      message\n      __typename\n    }\n    isNginxErrors\n    __typename\n  }\n}\n"
}
'@

    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf/graphql"
    $headers = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $($token)"
    }
    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    if ($response -and $response.data -and $response.data.publishChanges) {
        Write-Host "Changes published successfully."
        $publishResult = $response.data.publishChanges
        Write-Host "Is Valid: $($publishResult.isValid)"
        if ($publishResult.errors) {
            Write-Host "Errors:"
            foreach ($error in $publishResult.errors) {
                Write-Host " - $($error.message)"
            }
        }
        if ($publishResult.warnings) {
            Write-Host "Warnings:"
            foreach ($warning in $publishResult.warnings) {
                Write-Host " - $($warning.message)"
            }
        }
        # Write-Host "Is Nginx Errors: $($publishResult.isNginxErrors)"
    } else {
        Write-Host "Failed to publish changes."
        exit 1 
    }
}


function main() {
    $token = login
    if (-not $token) {
        Write-Host "Failed to login and retrieve token."
        exit 1
    }

    # Get all assets
    $assets = getApiAssets($token)
    if (-not $assets) {
        Write-Host "No assets found."
        exit 1
    }

    # Example: Get details of the first asset
    # if ($assets.Count -gt 0) {
    #     $firstAssetId = $assets[0].id
    #     Write-Host "Retrieving details for asset ID: $firstAssetId"
    #     $assetDetails = getAsset $token $firstAssetId
    #     if ($assetDetails) {
    #         Write-Host "Asset Details: $($assetDetails | ConvertTo-Json -Depth 10)"
    #     }
    # }

    Write-Host ""

    # iterate all assets
    foreach ($asset in $assets) {
        Write-Host ""
        Write-Host "Processing Asset ID: $($asset.id), Name: $($asset.name), Type: $($asset.assetType)"
        $assetDetails = getAsset $token $asset.id
        if ($assetDetails) {

            Write-Host "  Tags: $($assetDetails.tags | ForEach-Object { $_.tag } | Out-String)"
            $isManagedWhitelist = ($assetDetails.tags | ForEach-Object { $_.tag }) -contains "MANAGED_WHITELIST"
            if ($isManagedWhitelist) {
                Write-Host "  !!! managed whitelist."

                # has Exception parameterType
                $hasExceptionParameter = $assetDetails.behaviors | Where-Object { $_.parameterType -eq "Exception" }
                if ($hasExceptionParameter) {
                    Write-Host "  Asset has Exception parameterType."

                    # make sure that excusion rulebase has rule with comment "WHITE_LIST1"
                    $exceptionRulebase = $assetDetails.behaviors | Where-Object { $_.parameterType -eq "Exception" -and $_.exceptions }
                    $exceptionRulebaseId = $exceptionRulebase.id
                    $exceptionRulebaseRules = $exceptionRulebase.exceptions
                    # Write-Host "all exceptions: $($exceptionRulebaseRules | ConvertTo-Json -Depth 10)"
                    # Write-Host "Rulebase id: $exceptionRulebaseId"
                    $whiteListRule = $exceptionRulebaseRules | Where-Object { $_.comment -like "*WHITE_LIST1*" } | Select-Object -First 1
                    # Write-Host "Whitelist rule: $($whiteListRule | ConvertTo-Json -Depth 10)"
                    if ($whiteListRule) {
                        Write-Host "  WHITE_LIST1 Exception rule already exists."
                    } else {
                        addExceptionRule $token $whitelistedIps $exceptionRulebaseId $exceptionRulebase[0].id 
                    }

                } else {
                    Write-Host "  Asset does NOT have Exception parameterType."

                    
                    $whitelistRulebase = addWhitelistRulebase $token $whitelistedIps $asset.id
                    #Write-Host "  Whitelist rulebase created: $($whitelistRulebase | ConvertTo-Json -Depth 10)"
                }
            } else {
                # Write-Host "  Asset is NOT managed whitelist."
            }
            # Write-Host "Asset Details: $($assetDetails | ConvertTo-Json -Depth 10)"

            # iterate behaviours of parameterType Exceprion - in exceptions field array
            if ($assetDetails.behaviors) {
                foreach ($behavior in $assetDetails.behaviors) {
                    if ($behavior.parameterType -eq "Exception") {
                        Write-Host "Behavior ID: $($behavior.id), Name: $($behavior.name), Parameter Type: $($behavior.parameterType)"
                        if ($behavior.exceptions) {
                            foreach ($exception in $behavior.exceptions) {
                                Write-Host ""
                                Write-Host "  Exception ID: $($exception.id), Comment: $($exception.comment)"
                                # Write-Host "  Exception ID: $($exception.id), Match: $($exception.match), Actions: $($exception.actions | ConvertTo-Json -Depth 10), Comment: $($exception.comment)"
                                #Write-Host "  Exception Metadata: $($exception.metadata | ConvertTo-Json -Depth 10)"
                                #Write-Host "  Supported Practices Types: $($exception.supportedPracticesTypes | ConvertTo-Json -Depth 10)"

                                # iterate change list of exception $ruleUpdates
                                
                                    foreach ($update in $ruleUpdates) {
                                        # Write-Host "  Rule Update match tag: $($update.updateTag), Action: $(($update.fields | ConvertTo-Json -Depth 10))"
                                        # if $exception.comment string includes $update.updateTag
                                        if ($exception.comment -like "*$($update.updateTag)*") {
                                            # Write-Host "[UPDATE]  Update Tag: $($update.updateTag) found in exception comment."
                                            # update the match field with the new value
                                            # Write-Host "[UPDATE]  Updating fields " ($update.fields | ConvertTo-Json -Depth 10) "in exception ID: $($exception.id) of behavior ID: $($behavior.id)"

                                            $res = updateException $token $behavior.id $exception.id $update.fields $exception
                                        }
                                    }
                                
                            }
                        }
                    }
                }
            }
        } else {
            Write-Host "Failed to retrieve details for asset ID: $($asset.id)"
        }
    }

    Write-Host ""
    Write-Host "All assets processed. Publishing changes..."
    publish $token
    Write-Host "All assets processed and changes published.REMEMBER TO ENFORCE THE CHANGES IN THE WAF PORTAL."
}

main
