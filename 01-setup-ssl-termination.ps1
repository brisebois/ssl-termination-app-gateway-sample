# credentialing

$CertPassword    ='alex123'

$DnsNames         = "*.delete.me", "*.scm.delete.me"
$CertFileFullPath = "C:\temp\delete.me.pfx"
$SecurePassword   = ConvertTo-SecureString -String $CertPassword -AsPlainText -Force
$NewCert          = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $DnsNames 

Export-PfxCertificate -FilePath $CertFileFullPath -Password $SecurePassword -Cert $NewCert  

$DnsNames         = "*.alexandrebrisebois.com"
$CertFileFullPath = "C:\temp\alexandrebrisebois.com.pfx"
$SecurePassword   =ConvertTo-SecureString -String $CertPassword -AsPlainText -Force
$NewCert          = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $DnsNames 

Export-PfxCertificate -FilePath $CertFileFullPath -Password $SecurePassword -Cert $NewCert  

# $(Get-AzureRmApplicationGateway -Name 'albriseb' -ResourceGroupName 'delete').ProvisioningState

# setup via cloud shell

$GateWayName = 'delete-waf'
$RgName = 'delete'

$backendIpAddress = '10.1.0.4'

# setup frontend port

$gateway =  Get-AzureRmApplicationGateway `
                -Name $GateWayName `
                -ResourceGroupName $RgName

$gateway = Add-AzureRmApplicationGatewayFrontendPort `
    -Name 'AlexandrebriseboisFrontendPort' `
    -Port 443 `
    -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway

# setup SSL cert

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$pwd = ConvertTo-SecureString `
  -String $CertPassword `
  -Force `
  -AsPlainText

$gateway = Add-AzureRmApplicationGatewaySslCertificate `
  -Name "AlexandrebriseboisComAppGwCert" `
  -CertificateFile "$home\clouddrive\alexandrebrisebois.com.pfx" `
  -Password $pwd `
  -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway

# setup http listener (frontend)

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$cert = Get-AzureRmApplicationGatewaySslCertificate -Name 'AlexandrebriseboisComAppGwCert' -ApplicationGateway $gateway
$fipconfig = Get-AzureRmApplicationGatewayFrontendIPConfig -Name 'appGatewayFrontendIP' -ApplicationGateway $gateway
$frontendPort = Get-AzureRmApplicationGatewayFrontendPort -Name "AlexandrebriseboisFrontendPort" -ApplicationGateway $gateway 

$gateway = Add-AzureRmApplicationGatewayHttpListener `
  -Name 'AlexandrebriseboisHttpsListener' `
  -Protocol Https `
  -FrontendIPConfiguration $fipconfig `
  -FrontendPort $frontendPort `
  -SslCertificate $cert `
  -HostName 'www.alexandrebrisebois.com' `
  -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway

# setup backend pool with ILB IP

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$gateway = Add-AzureRmApplicationGatewayBackendAddressPool `
    -Name 'AlexandrebriseboisBackendAddressPool' `
    -BackendIPAddresses $backendIpAddress `
    -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway

# setup backend health probe over HTTP (80) with custom hostname

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$gateway = Add-AzureRmApplicationGatewayProbeConfig `
    -Name 'AlexandrebriseboisProbe' `
    -Protocol Http `
    -Path '/' `
    -Interval 60 `
    -UnhealthyThreshold 3 `
    -Timeout 120 `
    -HostName 'www.alexandrebrisebois.com' `
    -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway

# setup Backend Http Settings (communicate over HTTP (80))

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$probe = Get-AzureRmApplicationGatewayProbeConfig -Name 'AlexandrebriseboisProbe' -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayBackendHttpSettings `
    -Name 'AlexandrebriseboisHttpSettings' `
    -Port 80 `
    -Protocol Http `
    -Path '/' `
    -RequestTimeout 120 `
    -HostName 'www.alexandrebrisebois.com' `
    -Probe $probe `
    -CookieBasedAffinity Disabled `
    -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway

# setup Request Routing Rule from Frontend (SSL) to Backend (HTTP)

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

$httpListener = Get-AzureRmApplicationGatewayHttpListener -Name 'AlexandrebriseboisHttpsListener' -ApplicationGateway $gateway
$backendpool = Get-AzureRmApplicationGatewayBackendAddressPool -Name 'AlexandrebriseboisBackendAddressPool' -ApplicationGateway $gateway
$httpSettings = Get-AzureRmApplicationGatewayBackendHttpSettings -Name 'AlexandrebriseboisHttpSettings' -ApplicationGateway $gateway

$gateway =  Add-AzureRmApplicationGatewayRequestRoutingRule `
    -Name 'AlexandrebriseboisRule' `
    -RuleType Basic `
    -HttpListener $httpListener `
    -BackendAddressPool $backendpool `
    -BackendHttpSettings $httpSettings `
    -ApplicationGateway $gateway

Set-AzureRmApplicationGateway -ApplicationGateway $gateway

#clean up

# $gateway =  Get-AzureRmApplicationGateway -Name $GateWayName -ResourceGroupName $RgName

# $gateway = Remove-AzureRmApplicationGatewayBackendAddressPool -Name 'appGatewayBackendPool' -ApplicationGateway $gateway
# $gateway = Remove-AzureRmApplicationGatewayFrontendPort -Name 'appGatewayFrontendPort' -ApplicationGateway $gateway
# $gateway = Remove-AzureRmApplicationGatewayBackendHttpSettings -Name 'appGatewayBackendHttpSettings' -ApplicationGateway $gateway
# $gateway = Remove-AzureRmApplicationGatewayHttpListener -Name 'appGatewayHttpListener' -ApplicationGateway $gateway
# $gateway = Remove-AzureRmApplicationGatewayRequestRoutingRule -Name 'rule1' -ApplicationGateway $gateway

# Set-AzureRmApplicationGateway -ApplicationGateway $gateway