$GateWayName = 'delete-waf'
$RgName = 'delete'

$gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$gateway =  Add-AzureRmApplicationGatewayFrontendPort `
                -Name httpPort  `
                -Port 80 `
                -ApplicationGateway $gateway

$httpPort = Get-AzureRmApplicationGatewayFrontendPort `
                -Name httpPort `
                -ApplicationGateway $gateway

$fipconfig = Get-AzureRmApplicationGatewayFrontendIPConfig -Name 'appGatewayFrontendIP' `
                                                           -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayHttpListener `
                -Name httpListener `
                -Protocol Http `
                -FrontendPort $httpPort `
                -FrontendIPConfiguration $fipconfig `
                -ApplicationGateway $gateway

$httpsListener = Get-AzureRmApplicationGatewayHttpListener `
                -Name 'AlexandrebriseboisHttpsListener' `
                -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayRedirectConfiguration -Name httpToHttps `
                -RedirectType Permanent `
                -TargetListener $httpsListener `
                -IncludePath $true `
                -IncludeQueryString $true `
                -ApplicationGateway $gateway

$httpListener = Get-AzureRmApplicationGatewayHttpListener `
                -Name httpListener `
                -ApplicationGateway $gateway

$redirectConfig = Get-AzureRmApplicationGatewayRedirectConfiguration `
                -Name httpToHttps `
                -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayRequestRoutingRule `
                -Name httpsRedirect `
                -RuleType Basic `
                -HttpListener $httpListener `
                -RedirectConfiguration $redirectConfig `
                -ApplicationGateway $gateway

Set-AzureRmApplicationGateway -ApplicationGateway $gateway