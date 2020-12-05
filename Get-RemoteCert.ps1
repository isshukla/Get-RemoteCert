<#
 .Synopsis
  Get the Certificate details for any Website, allows user to download the certificate. This can be used for keeping track of the certificate details, change history.
  
 .Description
  Get the Certificate details for any Website, allows user to download the certificate. This can be used for keeping track of the certificate details, change history.
  
 .Parameter URL
  URL, in complete format
  
 .Example
  Get-RemoteCert -URL https://Bing.com/
  Get-RemoteCert -URL https://Bing.com/ -Export
  
#>

#------------------------------------------------------------------------------
#
#
# THIS CODE AND ANY ASSOCIATED INFORMATION ARE PROVIDED “AS IS” WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
# FOR A PARTICULAR PURPOSE. THE ENTIRE RISK OF USE, INABILITY TO USE, OR
# RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
#
#------------------------------------------------------------------------------


Function Get-RemoteCert {

Param(

    [Parameter(Mandatory=$true,
    ValueFromPipeline=$true)]
    [system.uri]$URL,

    [Parameter(Mandatory=$false)]
    [Switch]$Export

)



# Disabling Certificate check
#[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$True}


# Server part

 if ($url.Scheme -eq 'https'){

$web_server = [net.webrequest]::Create($url)

# Disable Redirect and Cache Policy
$web_server.AllowAutoRedirect=$false
$cachepol = [System.Net.Cache.RequestCacheLevel]::NoCacheNoStore
$web_server.CachePolicy=$cachepol

Try{
$web_Server_res = $web_server.GetResponse()
}
Catch
{
$err = $_
}
Write-Error $($err.Exception.InnerException.Message)

$web_Server_res.Close()

$Server_IP_Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($web_server.ServicePoint.Certificate)


#Date
$date = get-date

#Expire
$exp = $Server_IP_Cert.NotAfter - $date


# Custom Object part
$Certificatedetails = New-Object -TypeName PSObject

$Certificatedetails | Add-Member -Name TestDate -MemberType Noteproperty -Value $($date.ToUniversalTime())
$Certificatedetails | Add-Member -Name url -MemberType Noteproperty -Value $($web_server.Address.Host)
$Certificatedetails | Add-Member -Name Thumbprint -MemberType Noteproperty -Value $($Server_IP_Cert.Thumbprint)
$Certificatedetails | Add-Member -Name Subject -MemberType Noteproperty -Value $($Server_IP_Cert.Subject)
$Certificatedetails | Add-Member -Name Issuer -MemberType Noteproperty -Value $($Server_IP_Cert.Issuer)
$Certificatedetails | Add-Member -Name NotAfter -MemberType Noteproperty -Value $($Server_IP_Cert.NotAfter)
$Certificatedetails | Add-Member -Name NotBefore -MemberType Noteproperty -Value $($Server_IP_Cert.NotBefore)
$Certificatedetails | Add-Member -Name DNSnamelist -MemberType Noteproperty -Value $($Server_IP_Cert.DNSnamelist)
$Certificatedetails | Add-Member -Name DaysToExpire -MemberType Noteproperty -Value $($exp.Days)
$Certificatedetails | Add-Member -Name SignatureAlgorithm -MemberType Noteproperty -Value $($Server_IP_Cert.SignatureAlgorithm.FriendlyName)
$Certificatedetails | Add-Member -Name Version -MemberType Noteproperty -Value $($Server_IP_Cert.Version)


# Output
$Certificatedetails

#Export
if($Export -eq $true){
Write-host "Certificate will be exported to $($home)" -ForegroundColor Green
$certexpo = $Server_IP_Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert, "")
$outPfxPath = $home+"\$($web_server.Address.Host)-$($Server_IP_Cert.Thumbprint).cer"
[io.file]::WriteAllBytes($outPfxPath, $certexpo)
}
}
Else{Write-Warning "Enter HTTPS URL"}


} # Func End

Export-ModuleMember -Function Get-RemoteCert

