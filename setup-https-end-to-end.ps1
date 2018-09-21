$CertPassword    ='alex123'

$DnsNames         = "*.alexandrebrisebois.com"
$CertFileFullPath = "C:\temp\alexandrebrisebois.com.pfx"
$CerFileFullPath = "C:\temp\alexandrebrisebois.com.cer"

# Make SelfSigned Cert

# https://docs.microsoft.com/en-us/azure/application-gateway/application-gateway-end-to-end-ssl-powershell 

# For end-to-end SSL encryption, the back end must be whitelisted with the application gateway. 
# You need to upload the public certificate of the back-end servers to the application gateway. 
# Adding the certificate ensures that the application gateway only communicates with known back-end instances. 
# This further secures the end-to-end communication.

$SecurePassword = ConvertTo-SecureString `
                    -String $CertPassword `
                    -AsPlainText -Force

$NewCert = New-SelfSignedCertificate `
                    -CertStoreLocation Cert:\CurrentUser\My `
                    -DnsName $DnsNames

Export-PfxCertificate `
                    -FilePath $CertFileFullPath `
                    -Password $SecurePassword `
                    -Cert $NewCert  

Export-Certificate  -FilePath $CerFileFullPath `
                    -Cert $NewCert

# VAR Configurations

$GateWayName = 'delete-waf'
$RgName = 'delete'

$sslCertName = 'SSLCert'
$authCertName = 'AuthCert'                   
$httpsListenerName = 'Https443Listener'
$httpListenerName = 'Http80Listener'

$frontendPortName = 'FrontendPort443'
$frontendPortHttpName = 'FrontendPort80'

$frontendIpConfig = 'appGatewayFrontendIP'

$hostname = 'www.alexandrebrisebois.com'

$backendAddressPoolName = 'BackendAddressPool'
$backendIpAddress = '10.1.0.4'

$httpsProbeName = 'HttpsProbe'

$httpsSettingsName = 'HttpsSettings'

$httpsRequestRoutingRuleName = 'HttpsRule'

$httpToHttpsRedirectConfigurationName = "httpToHttpsRedirectConfiguration"

# Fetch deployed Application Gateway from Server

$gateway =  Get-AzureRmApplicationGateway `
                -Name $GateWayName `
                -ResourceGroupName $RgName

# cleanup defaults

#  $gateway = Remove-AzureRmApplicationGatewayBackendAddressPool -Name 'appGatewayBackendPool' -ApplicationGateway $gateway
#  $gateway = Remove-AzureRmApplicationGatewayFrontendPort -Name 'appGatewayFrontendPort' -ApplicationGateway $gateway
#  $gateway = Remove-AzureRmApplicationGatewayBackendHttpSettings -Name 'appGatewayBackendHttpSettings' -ApplicationGateway $gateway
#  $gateway = Remove-AzureRmApplicationGatewayHttpListener -Name 'appGatewayHttpListener' -ApplicationGateway $gateway
#  $gateway = Remove-AzureRmApplicationGatewayRequestRoutingRule -Name 'rule1' -ApplicationGateway $gateway

# $gateway

# Add Certificates

$pwd = ConvertTo-SecureString `
                    -String $CertPassword `
                    -Force `
                    -AsPlainText

$gateway = Add-AzureRmApplicationGatewaySslCertificate `
                    -Name $sslCertName `
                    -CertificateFile $CertFileFullPath `
                    -Password $pwd `
                    -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayAuthenticationCertificate `
                    -Name $authCertName `
                    -CertificateFile $CerFileFullPath `
                    -ApplicationGateway $gateway

# Add Frontend Port

$gateway = Add-AzureRmApplicationGatewayFrontendPort `
                    -Name $frontendPortName `
                    -Port 443 `
                    -ApplicationGateway $gateway

# Add Http Listeners

$cert = Get-AzureRmApplicationGatewaySslCertificate `
                    -Name $sslCertName `
                    -ApplicationGateway $gateway

$fipconfig = Get-AzureRmApplicationGatewayFrontendIPConfig `
                    -Name $frontendIpConfig `
                    -ApplicationGateway $gateway

$frontendPort = Get-AzureRmApplicationGatewayFrontendPort `
                    -Name $frontendPortName `
                    -ApplicationGateway $gateway 

$gateway = Add-AzureRmApplicationGatewayHttpListener `
                    -Name $httpsListenerName `
                    -Protocol Https `
                    -FrontendIPConfiguration $fipconfig `
                    -FrontendPort $frontendPort `
                    -SslCertificate $cert `
                    -HostName $hostname `
                    -ApplicationGateway $gateway

# Add Backend Pool

$gateway = Add-AzureRmApplicationGatewayBackendAddressPool `
                    -Name $backendAddressPoolName `
                    -BackendIPAddresses $backendIpAddress `
                    -ApplicationGateway $gateway

# Configure Backend Probe

$httpListener = Get-AzureRmApplicationGatewayHttpListener `
                    -Name $httpsListenerName `
                    -ApplicationGateway $gateway

$backendpool = Get-AzureRmApplicationGatewayBackendAddressPool `
                    -Name $backendAddressPoolName `
                    -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayProbeConfig `
                    -Name $httpsProbeName `
                    -Protocol Https `
                    -Path '/' `
                    -Interval 60 `
                    -UnhealthyThreshold 3 `
                    -Timeout 120 `
                    -HostName $hostname `
                    -ApplicationGateway $gateway

$probe = Get-AzureRmApplicationGatewayProbeConfig `
                    -Name $httpsProbeName `
                    -ApplicationGateway $gateway

# Add Backend Https Http Settings

$authCert = Get-AzureRmApplicationGatewayAuthenticationCertificate `
                    -Name $authCertName `
                    -ApplicationGateway $gateway

$gateway = Add-AzureRmApplicationGatewayBackendHttpSettings `
                    -Name $httpsSettingsName `
                    -Port 443 `
                    -Protocol Https `
                    -Path '/' `
                    -RequestTimeout 120 `
                    -AuthenticationCertificates $authCert `
                    -HostName $hostname `
                    -Probe $probe `
                    -CookieBasedAffinity Disabled `
                    -ApplicationGateway $gateway

$httpsSettings = Get-AzureRmApplicationGatewayBackendHttpSettings `
                    -Name $httpsSettingsName `
                    -ApplicationGateway $gateway

# Add Request Routing Rule

$gateway =  Add-AzureRmApplicationGatewayRequestRoutingRule `
                    -Name $httpsRequestRoutingRuleName `
                    -RuleType Basic `
                    -HttpListener $httpListener `
                    -BackendAddressPool $backendpool `
                    -BackendHttpSettings $httpsSettings `
                    -ApplicationGateway $gateway

# Setup HTTP -> HTTPS Redirect

# Add Frontend HTTP Port

$gateway =  Add-AzureRmApplicationGatewayFrontendPort `
                    -Name $frontendPortHttpName  `
                    -Port 80 `
                    -ApplicationGateway $gateway

$httpPort = Get-AzureRmApplicationGatewayFrontendPort `
                    -Name $frontendPortHttpName `
                    -ApplicationGateway $gateway

# Add Frontend HTTP Listener

$gateway = Add-AzureRmApplicationGatewayHttpListener `
                    -Name $httpListenerName `
                    -Protocol Http `
                    -FrontendPort $httpPort `
                    -FrontendIPConfiguration $fipconfig `
                    -ApplicationGateway $gateway

# Add Redirect Configuraiton

$gateway = Add-AzureRmApplicationGatewayRedirectConfiguration `
                    -Name $httpToHttpsRedirectConfigurationName `
                    -RedirectType Permanent `
                    -TargetListener $httpsListener `
                    -IncludePath $true `
                    -IncludeQueryString $true `
                    -ApplicationGateway $gateway


# Apply Configuration to Application Gateway

Set-AzureRmApplicationGateway `
                    -ApplicationGateway $gateway                     