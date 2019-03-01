# Lastpass Powershell Module
# Copyright (C) 2019 Steven Loudermilk
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


#TODO: Get from module manifest
$Script:LP_CLIENT_VERSION = '0.0.1'

$Script:Session
$Script:Blob
$Script:WebSession

Function Connect-Lastpass {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[PSCredential] $Credential,

		[String] $OTPCode
	)

	$EncodedUsername = [Byte[]][Char[]] $Credential.UserName.ToLower()
	$EncodedPassword = [Byte[]][Char[]] $Credential.GetNetworkCredential().Password
	[Int] $Iterations = Invoke-RestMethod 'https://lastpass.com/iterations.php' -Body @{email=$Credential.Username.ToLower()}
	Write-Debug "Iterations: $Iterations"

	Switch($Iterations){
		1 {
			$SHA256 = [System.Security.Cryptography.SHA256Managed]::New()
			$Key = $SHA256.ComputeHash($EncodedUsername + $EncodedPassword)
			$Hash = $SHA256.ComputeHash(
				[Byte[]][Char[]] (
					(($Key | ForEach { "{0:x2}" -f $_ }) -join '') + 
					$Credential.GetNetworkCredential().Password
				)
			)
			Break
		}
		{$_ -gt 1} {
			$SHA256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
			$HashSize = 32

			$Key = [System.Security.Cryptography.Rfc2898DeriveBytes]::New(
				$EncodedPassword, 
				$EncodedUsername, 
				$Iterations, 
				$SHA256
			).GetBytes($HashSize)

			$Hash = [System.Security.Cryptography.Rfc2898DeriveBytes]::New(
				$Key,
				$EncodedPassword,
				1,
				$SHA256
			).GetBytes($HashSize)
			Break
		}
		Default {Throw "Invalid Iteration value: '$Iterations'"}
	}
	$Hash = ($Hash | ForEach { "{0:x2}" -f $_ }) -join ''
	Write-Debug "Hash: $Hash"

	$Param = @{
		URI = 'https://lastpass.com/login.php'
		Method = 'Post'
		Body = @{
			xml						= '2'
			username				= $Credential.Username.ToLower()
			hash					= $Hash
			iterations				= "$Iterations"
			includeprivatekeyenc	= '1'
			method					= 'cli'
			outofbandsupported		= '1'
			#UUID 					= Get-Random # Gen random?
		}
		SessionVariable = 'WebSession'
	}
	$Param | Out-String | Write-Debug
	$Response = (Invoke-RestMethod @Param).Response

	#TODO: Change this to While($Response.Error)?
	If($Response.Error){
		Switch -Regex ($Response.Error.Cause){
			'googleauthrequired|otprequired' {
				If(!$OTPCode){
					$OTPCode = Read-Host 'Enter multifactor authentication code'
				}
				$Param.Body.otp = $OTPCode
				$Response = (Invoke-RestMethod @Param).Response

				#'multifactorresponsefailed'
				Break
			}
			'outofbandrequired' { 
				$Response.Error.OutOfBandType
				Break
			}
			#'verifydevice' -> Default: Throw message
			Default { Throw $Response.Error.Message }
		}
	}

	If($Response.OK){
		$Script:Session = [PSCustomObject] @{
			UID					= $Response.OK.UID
			SessionID			= $Response.OK.SessionID
			Token				= $Response.OK.Token
			EncryptedPrivateKey = $Response.OK.PrivateKeyEnc
			Iterations			= $Iterations
			Key					= $Key
		}
	}
	# Download blob
	# Sync-LastpassBlob

	Return [PSCustomObject] @{
		Email = $Credential.Username
		SessionID = $Script:Session.SessionID
	}

}



Function Sync-LastpassBlob {

	[CmdletBinding()]
	Param()

	$Cookie = [System.Net.Cookie]::New(
		'PHPSESSID',
		[System.Web.HttpUtility]::UrlEncode($Session.SessionID),
		'/',
		'lastpass.com'
	)
	$Script:WebSession = [Microsoft.Powershell.Commands.WebRequestSession]::New()
	$WebSession.Cookies.Add($Cookie)
	If(!$?){ Throw 'Unable to create session' }

	$Param = @{
		WebSession = $WebSession
		URI = 'https://lastpass.com/getaccts.php'
		Body = @{ RequestSrc = 'cli' }
	}
	$Response = (Invoke-RestMethod @Param).Response

	#Parse blob
	# Error

	$Script:Blob = $Response
	$Script:LastSyncTime = Get-Date

	#Outputs
	#FIXME: This should only be output if debugging
	Write-Output $Response
}

#FIXME! Remove; for debugging purposes only
Function Get-Session {
	Return [PSCustomObject] @{
		WebSession = $WebSession
		Session = $Session
	}
}



Function Get-Account {

	Param(

	)

	# $Origin = [DateTime] '1970-01-01 00:00:00'

	# If($_.PWProtect){
		# Prompt for password and die if incorrect
	#}
	# [PSCustomObject] @{
	# 	ID = $_.ID
	# 	Name = ConvertFrom-LPEncrypted $_.Name
		# 	URL = ($URL -split '([a-f0-9]{2})' | ForEach {
		# 			If($_){ [Char][Convert]::ToByte($_,16) }
		# 		}) -join ''
	# 	Group = ConvertFrom-LPEncrypted $_.Group
	# 	Username = ConvertFrom-LPEncrypted $_.Username
	#	Password = ConvertFrom-LPEncrypted $_.Login.p 
	# 	Extra = ConvertFrom-LPEncrypted $_.Extra #Note content
	#	
	#	Favorite = !!($_.Fav)
	#	LastModified = $Origin.AddSeconds($_.Last_Modified)
	#	LastAccessed = $Origin.AddSeconds($_.Last_Touch)
	#	LaunchCount = $_.Launch_Count
	#	Bookmark = !!($_.IsBookmark)
	#	
	# 	#sn= SecureNote?
	# }
	
	
}


<#
New-Account {}


Set-Account {}


Remove-Account {}


New-Note {}


Get-Note {}


Set-Note {}


Remove-Note {}


New-Folder {}


Get-Folder {}


Set-Folder {}
	-Sharing


Remove-Folder {}


Reset-MasterPassword {}


Move-Folder?


#>

Function ConvertFrom-LPEncryptedString {
	Param (
		[Parameter(
			Mandatory,
			ValueFromPipeline, 
			ValueFromPipelineByPropertyName,
			Position = 0
		)]
		[AllowEmptyString()]
		[String[]] $Value
	)

	BEGIN {
		$AES = [System.Security.Cryptography.AesManaged]::New()
		$AES.KeySize = 256
		$AES.Key = $Session.Key
	}
	
	PROCESS {
		$Value | ForEach {
			If($_[0] -eq '!'){ #-and
			#$_.Length -gt 32 -and
			#('!{0}|{1}' -f $IV, $Data).Length % 16 -eq 1){
				#TODO: Test whether Base64 conversion is necessary
				$AES.Mode = [Security.Cryptography.CipherMode]::CBC
				$Data = [Convert]::FromBase64String($_[26..($_.Length-1)])
				$AES.IV = [Convert]::FromBase64String($_[1..24])
			}	
			Else{
				Write-Debug 'ECB'
				$AES.Mode = [Security.Cryptography.CipherMode]::ECB
				$Data = [Convert]::FromBase64String($_)
				$AES.IV = [Byte[]] '0'*16
			}
			
			$AES | Out-String | Write-Debug
			$Decryptor = $AES.CreateDecryptor()

			[Char[]] $Decryptor.TransformFinalBlock(
				$Data, 
				0, 
				$Data.length
			) -join ''
		}
	}
}