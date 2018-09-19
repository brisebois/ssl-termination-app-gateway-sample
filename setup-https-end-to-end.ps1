$GateWayName = 'delete-waf'
$RgName = 'delete'

$gateway =  Get-AzureRmApplicationGateway `
                -Name $GateWayName `
                -ResourceGroupName $RgName

$httpListener = Get-AzureRmApplicationGatewayHttpListener -Name 'AlexandrebriseboisHttpsListener' -ApplicationGateway $gateway
$backendpool = Get-AzureRmApplicationGatewayBackendAddressPool -Name 'AlexandrebriseboisBackendAddressPool' -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayProbeConfig `
    -Name 'HttpsProbe' `
    -Protocol Https `
    -Path '/' `
    -Interval 60 `
    -UnhealthyThreshold 3 `
    -Timeout 120 `
    -HostName 'www.alexandrebrisebois.com' `
    -ApplicationGateway $gateway

$probe = Get-AzureRmApplicationGatewayProbeConfig `
            -Name 'HttpsProbe' `
            -ApplicationGateway $gateway

# $cert = Get-AzureRmApplicationGatewaySslCertificate -Name 'AlexandrebriseboisComAppGwCert' -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayBackendHttpSettings `
        -Name 'AlexandrebriseboisHttpsSettings' `
        -Port 443 `
        -Protocol Https `
        -Path '/' `
        -RequestTimeout 120 `
       # -AuthenticationCertificates $cert `
        -HostName 'www.alexandrebrisebois.com' `
        -Probe $probe `
        -CookieBasedAffinity Disabled `
        -ApplicationGateway $gateway

$httpsSettings = Get-AzureRmApplicationGatewayBackendHttpSettings -Name 'AlexandrebriseboisHttpsSettings' -ApplicationGateway $gateway
 
$gateway =  Remove-AzureRmApplicationGatewayRequestRoutingRule `
            -Name 'AlexandrebriseboisRule' `
            -ApplicationGateway $gateway

$gateway =  Add-AzureRmApplicationGatewayRequestRoutingRule `
            -Name 'AlexandrebriseboisRule' `
            -RuleType Basic `
            -HttpListener $httpListener `
            -BackendAddressPool $backendpool `
            -BackendHttpSettings $httpsSettings `
            -ApplicationGateway $gateway
        
Set-AzureRmApplicationGateway -ApplicationGateway $gateway