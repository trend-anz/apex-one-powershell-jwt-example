function create_checksum(
    $http_method = $null,
    $raw_url = $null,
    $headers = $null,
    $request_body = $null)
        {
        $string_to_hash = $http_method.ToUpper() + "|" + $raw_url.ToLower() + "|" + $headers + "|" + $request_body
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = [Convert]::ToBase64String($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($string_to_hash)))
        return $hash
        }

function create_jwt_token(
    $application_id = $null,
    $api_key = $null, 
    $http_method = $null, 
    $raw_url = $null, 
    $headers= $null, 
    $request_body = $null,
    $iat = (New-TimeSpan -Start (Get-Date "01/01/1970") -End (Get-Date).ToUniversalTime()).TotalSeconds, 
    $algorithm = "HS256", 
    $version = "V1")
        {

        $checksum = create_checksum -http_method $http_method -raw_url $raw_url -headers $headers -request_body $request_body
        
        $payload = [ordered]@{
            "appid" = $application_id
            "iat" = $iat
            "version" = $version
            "checksum" = $checksum
        } | Convertto-json -Compress

        $jwtheader = [ordered]@{
            "typ" = "JWT"
            "alg" = "HS256"
        } | ConvertTo-Json -Compress
        
        $headersEncoded = Get-Base64UrlEncodeFromString -inputString $jwtheader
        $payloadEncoded = Get-Base64UrlEncodeFromString -inputString $payload 

        $content = "$( $headersEncoded ).$( $payloadEncoded )"

        $signatureByte = Get-HMACSHA256 -data $content -key $api_key
        $signature = Get-Base64UrlEncodeFromByteArray -byteArray $signatureByte

        $jwt = "$( $headersEncoded ).$( $payloadEncoded ).$( $signature )"
 
        return $jwt
        
        }
Function Get-HMACSHA256 {

    param(
        [Parameter(Mandatory=$true)][String]$data,
        [Parameter(Mandatory=$true)][String]$key
    )
    
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256  
    $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($key)
    $bytesToSign = [Text.Encoding]::UTF8.GetBytes($data)
    $sign = $hmacsha.ComputeHash($bytesToSign)

    return $sign
}

Function Get-Base64UrlEncodeFromString {

    param(
            [Parameter(Mandatory=$true)][String]$inputString
    )

    $inputBytes = [Text.Encoding]::UTF8.GetBytes($inputString)
    
    # Special "url-safe" base64 encode.
    $base64 = [System.Convert]::ToBase64String($inputBytes,[Base64FormattingOptions]::None).Replace('+', '-').Replace('/', '_').Replace("=", "")

    return $base64

}

Function Get-Base64UrlEncodeFromByteArray {
    
    param(
         [Parameter(Mandatory=$true)][byte[]]$byteArray
    )
   
    # Special "url-safe" base64 encode.
    $base64 = [System.Convert]::ToBase64String($byteArray,[Base64FormattingOptions]::None).Replace('+', '-').Replace('/', '_').Replace("=", "")

    return $base64

}

# Use this region to setup the call info of the TMCM server (server url, application id, api key)
$use_url_base = 'https://abcdef.manage.trendmicro.com:443'
$use_application_id = '<ApplicationID>'
$use_api_key = '<ApiKey>'

# This is the path for ProductAgents API
$productAgentAPIPath = '/WebApp/API/AgentResource/ProductAgents'
# currently Canonical-Request-Headers will always be empty
$canonicalRequestHeaders = ''

# This sample sends a get request to obtain agent info
$useQueryString = '?host_name=BENPFUOSCECLIEN'
$useRequestBody = ''
$raw_url = $productAgentAPIPath + $useQueryString

$http_method = "GET"
$iat = (New-TimeSpan -Start (Get-Date "01/01/1970") -End (Get-Date).ToUniversalTime()).TotalSeconds

$jwt_token = create_jwt_token -application_id $use_application_id -api_key $use_api_key -http_method $http_method -raw_url $raw_url -headers $canonicalRequestHeaders -request_body $useRequestBody -iat $iat

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer " + $jwt_token)

$fulluri = $use_url_base + $productAgentAPIPath + $useQueryString

$r = Invoke-WebRequest -Headers $headers -Uri $fulluri -Method $http_method -Body $useRequestBody
$r.StatusCode
$Content = $r.Content | ConvertFrom-Json
$Content.result_code
$Content.result_description
$Content.result_content
