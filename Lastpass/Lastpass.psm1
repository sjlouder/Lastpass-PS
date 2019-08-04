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

Using Namespace System.Security.Cryptography

$Script:Epoch = [DateTime] '1970-01-01 00:00:00'
$Script:Schema = @{
	
	Account = @{
		Fields = [Ordered] @{
			ID = 'String'
			Name = 'Encrypted'
			Group = 'Encrypted'
			URL = 'Hex'
			Note = 'Encrypted'
			Favorite = 'Boolean'
			SharedFromAID = 'String' #?
			Username = 'Encrypted'
			Password = 'Encrypted'
			PasswordProtect = 'Boolean'
			GeneratedPassword = 'Boolean' #?
			SecureNote = 'Boolean' #?
			LastModified = 'String'
			AutoLogin = 'Boolean' #?
			NeverAutofill = 'Boolean' #?
			RealmData = 'String' #?
			FIID = 'Skip' #?
			CustomJS = 'Skip' #?
			SubmitID = 'Skip' #?
			CaptchaID = 'Skip' #?
			URID = 'Skip' #?
			BasicAuth = 'Skip' #?
			Method = 'Skip' #?
			Action = 'Skip'
			GroupID = 'String' #?
			Deleted = 'Boolean' #?
			EncryptedAttachmentKey = 'String'
			AttachmentPresent = 'Boolean'
			IndividualShare = 'Boolean' #?
			NoteType = 'String' #?
			NoAlert = 'String' #?
			LastModifiedGMT = 'String' #?
			HasBeenShared = 'Boolean' #?
			LastPasswordChange = 'String' #?
			DateCreated = 'String' #?
			Vulnerable = 'Boolean' #?
		}
		DefaultFields = @(
			'Name'
			'Username'
			'Folder'
			'Favorite'
		)
	}
	Note = @{
		Fields = [Ordered] @{

		}
		DefaultFields = @(
			'Name'
			'Folder'
			'Favorite'
		)
	}
	SharedFolder = @{
		Fields = [Ordered] @{
			ID = 'String'
			RSAEncryptedFolderKey = 'Encrypted'
			Name = 'Encrypted'
			ReadOnly = 'Boolean'
			Unknown = 'String' #Not sure what this is
			AESFolderKey = 'Encrypted'
		}
		DefaultFields = @(

		)
	}
}


$Script:Session
$Script:Blob
$Script:WebSession
[TimeSpan] $Script:PasswordTimeout = New-Timespan
$Script:PasswordPrompt

Function Connect-Lastpass {

	<#
	.SYNOPSIS
	Logs in to Lastpass
	
	.DESCRIPTION
	Creates an authenticated session with the Lastpass service.
	If app based multifactor authentication is setup for the account,
	prompts for the one time password if it is not passed as a parameter.
	
	.PARAMETER Credential
	The Lastpass account credential
	.PARAMETER OneTimePassword
	The one time password generated by an multifactor authentication
	app, such as Google authenticator.
	If the account does is not setup for app based MFA, this
	parameter is ignored.
	
	.EXAMPLE
	Connect-Lastpass -Credential (Get-Credential)
	Logs in to Lastpass, prompting for the username and password
	
	.EXAMPLE
	Connect-Lastpass -Credential $Credential -OneTimePassword 158320
	Logs in to Lastpass, with the credentials saved in the $Credential
	variable. Includes the one time password.
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[PSCredential] $Credential,

		[String] $OneTimePassword
	)

	$Param = @{
		URI = 'https://lastpass.com/iterations.php'
		Body = @{email = $Credential.Username.ToLower()}
	}
	"Iterations parameters:`n{0}" -f ($Param.Body | Out-String) | Write-Debug
	[Int] $Iterations = Invoke-RestMethod @Param
	Write-Debug "Iterations: $Iterations"

	$Key = New-Key -Credential $Credential -Iterations $Iterations
	$Hash = New-LoginHash -Key $Key -Credential $Credential -Iterations $Iterations

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
	"Login parameters:`n{0}" -f ($Param.Body | Out-String) | Write-Debug
	$Response = (Invoke-RestMethod @Param).Response

	#TODO: Change this to While($Response.Error)?
	If($Response.Error){
		"Error received:`n{0}" -f $Response.Error.OuterXML | Write-Debug
		Switch -Regex ($Response.Error.Cause){
			OutOfBandRequired {
				#TODO
				#$Response.Error.OutOfBandType
				#Return $Response
				$Type = $Response.Error.OutOfBandName
				$Capabilities = $Response.Error.Capabilities -split ','
				If(!$Type -or !$Capabilities){ Throw 'Could not determine out-of-band type' }
				
				$Param.Body.outofbandrequest = 1
				$Prompt = "Complete multifactor authentication through $Type"
				If($Capabilities -contains 'Passcode' -and $Interactive -and !$OneTimePassword ){
					$Prompt += ' or enter a one time passcode: '
					Write-Host -NoNewLine $Prompt
					Do {
						$Response = (Invoke-RestMethod @Param).Response
						If($Response.Error.Cause -eq 'OutOfBandRequired'){
							$Param.Body.outofbandretry = 1
							$Param.Body.outofbandretryid = $Response.Error.RetryID
							
							While([Console]::KeyAvailable){
								$Input = [Console]::ReadKey($True)
								Write-Debug ("Key: {0} {1}" -f $Input.Key, ($Input.Key -eq 'Enter'))
								If( $Input.Key -eq 'Enter' ){
									Write-Debug $OneTimePassword
									$Param2 = $Param.Clone()
									$Param2.Body.outofbandrequest = 0
									$Param2.Body.outofbandretry = 0
									$Param2.Body.outofbandretryid = ''
									$Param2.Body.otp = $OneTimePassword
									$Param2.Body | Out-String | Write-Debug
									$Response = (Invoke-RestMethod @Param2).Response
									$OneTimePassword = $Null
									Break
								}
								$OneTimePassword += $Input.KeyChar
							}
						}
						ElseIf($Response.Error.Cause -eq 'MultiFactorResponseFailed'){
							Throw $Response.Error.Message
						}
						Start-Sleep 1
					}Until($Response.OK)
				}
				ElseIf($Capabilities -notcontains 'Passcode' -or !$Interactive){
					Write-Host -NoNewLine $Prompt
					Do {
						$Response = (Invoke-RestMethod @Param).Response
						If($Response.Error.Cause -eq 'OutOfBandRequired'){
							$Param.Body.outofbandretry = 1
							$Param.Body.outofbandretryid = $Response.Error.RetryID
						}
						ElseIf($Response.Error.Cause -eq 'MultiFactorResponseFailed'){
							Throw $Response.Error.Message
						}
						Start-Sleep 1
					}Until($Response.OK)

				}
			}
			{$_ -in 'GoogleAuthRequired', 'OTPRequired' -or ($_ -eq 'OutOfBandRequired' -and $OneTimePassword)} {
				If(!$OneTimePassword){
					If(!$Interactive){
						Throw ('Powershell is running in noninteractive mode. ' + 
							'Enter the one time password via the -OneTimePassword parameter.')
					}
					$OneTimePassword = Read-Host 'Enter multifactor authentication code'
				}
				$Param.Body.otp = $OneTimePassword
				$Response = (Invoke-RestMethod @Param).Response

				# TODO: Error checking
				#'multifactorresponsefailed'
			}
			#'verifydevice' -> Default: Throw message
			# Parse custombutton and customaction attributes
			Default { Throw $Response.Error.Message }
		}
	}
	$Response.OK | Out-String | Write-Debug
	If(!$Response.OK){ Throw 'Login unsuccessful' }
	
	$Script:Session = [PSCustomObject] @{
		UID					= $Response.OK.UID
		SessionID			= $Response.OK.SessionID
		Token				= $Response.OK.Token
		EncodedPrivateKey	= $Response.OK.PrivateKeyEnc
		PrivateKey			= [RSAParameters]::New()
		Iterations			= $Response.OK.Iterations
		Username			= $Response.OK.LPUsername
		Key					= $Key
	}
	
	If($Session.EncodedPrivateKey){
		If($Session.EncodedPrivateKey[0] -eq '!'){
			Write-Debug 'Version 2 private key encoding'
			$DecryptedKey = [Convert]::FromBase64String($Session.EncodedPrivateKey) -join '' |
				ConvertFrom-LPEncryptedString 
		}
		Else{
			Write-Debug 'Version 1 private key encoding'
			$DecryptedKey = '!{0}{1}' -f @(
				([char[]] $S.Session.Key -join ''),
				($Session.EncodedPrivateKey | ConvertFrom-Hex)
			) | ConvertFrom-LPEncryptedString
		}

		If(!$DecryptedKey){
			Write-Warning 'Failed to decrypt private key'
		}
		ElseIf($DecryptedKey -notmatch '.*ey<(.*)>LastPassPrivateKey$'){
			Write-Warning 'Failed to decode decrypted private key'
		}
		Else{
			$ASN1 = [Byte[]][Char[]] ($Matches[1] | ConvertFrom-Hex)
			# This is a ASN.1 encoding, do basic parsing
			$Sequence = (Read-ASN1Item -Blob $ASN1).Value
			$Index = 0
			1..2 | ForEach { $Index += (Read-ASN1Item -Blob $Sequence -Index $Index).Index }
			$Sequence2 = (Read-ASN1Item -Blob $Sequence -Index $Index).Value
			$Sequence3 = (Read-ASN1Item -Blob $Sequence2).Value
			$Index = (Read-ASN1Item -Blob $Sequence3).Index
			$Sequence4 = (Read-ASN1Item -Blob $Sequence3 -Index $Index).Value
			
			$RSAParameters = @()
			$Index = 0
			1..8 | ForEach {
				$Bytes = Read-ASN1Item -Blob $Sequence4 -Index $Index
				$Index = $Value.Index
				$ByteIndex = 0
				While($Bytes[$ByteIndex] -ne 0){$ByteIndex++}
				$Value = $Bytes[$ByteIndex..($Bytes.Length - 1)]
			}

			$Session.PrivateKey.Modulus = $RSAParameters[0]
			$Session.PrivateKey.Exponent = $RSAParameters[1]
			$Session.PrivateKey.D = $RSAParameters[2]
			$Session.PrivateKey.P =$RSAParameters[3]
			$Session.PrivateKey.Q = $RSAParameters[4]
			$Session.PrivateKey.DP = $RSAParameters[5]
			$Session.PrivateKey.DQ = $RSAParameters[6]
			$Session.PrivateKey.InverseQ = $RSAParameters[7]
			
		}
	}

	$Cookie = [System.Net.Cookie]::New(
		'PHPSESSID',
		[System.Web.HttpUtility]::UrlEncode($Script:Session.SessionID),
		'/',
		'lastpass.com'
	)

	$Script:WebSession = [Microsoft.Powershell.Commands.WebRequestSession]::New()
	$Script:WebSession.Cookies.Add($Cookie)
	If(!$?){ Throw 'Unable to create session' }

	Sync-Lastpass -Debug:$False | Out-Null

	If($PSBoundParameters.Debug){ Return $Response }

	[PSCustomObject] @{
		Email = $Credential.Username
		SessionID = $Script:Session.SessionID
	} | Write-Output

}



Function Sync-Lastpass {

	<#
	.SYNOPSIS
	Downloads Lastpass accounts from the server
	
	.DESCRIPTION
	Updates (overwrites) the local cache of Lastpass items with the latest version on the server.
	Decrypts the names of the items for later retrieval.

	.EXAMPLE
	Sync-LastpassBlob
	Downloads the Lastpass accounts from the server

	#>
	
	[CmdletBinding()]
	Param()

	Write-Verbose 'Syncing Lastpass information'
	
	$Param = @{
		WebSession = $Script:WebSession
		URI = 'https://lastpass.com/getaccts.php'
		Body = @{
			requestsrc = 'cli'
			mobile = '1'
			hasplugin = '3.0.23'
		}
		ErrorAction = 'Stop'
	}
	"Sync parameters:`n{0}" -f ($Param.Body | Out-String) | Write-Debug
	$Response = Invoke-RestMethod @Param

	If($Response.Error){ Throw $Response.Error.Cause }
	# If($PSBoundParameters.Debug){ Write-Output $Response }
	"Response:`n{0}" -f $Response | Write-Debug
	#$Response = ([char[]][Convert]::FromBase64String($Response)) -join ''
	$Script:LastSyncTime = Get-Date


	Write-Verbose 'Parsing data'
	$Index = 0
	$Script:Blob = @{
		Metadata = @{}
		Accounts = @()
		SharedFolders = @()
	}
	While($Index -lt ($Response.Length-8)){
		$ID = $Response[$Index..($Index+=3)] -join ''
		Write-Debug "ID: $ID"
		Write-Debug "Index: $Index"
		$Data = Read-Item -Blob $Response -Index ($Index+=1)
		$Index += $Data.Length + 4
		Write-Debug "After index: $Index"

		If(!$Blob.Metadata[$ID]){ $Blob.Metadata[$ID] = 1}
		Else{ $Blob.Metadata[$ID] += 1 }

		If($ID -eq 'ENDM' -and $Data -eq 'OK'){ Break }

		$ItemIndex = 0
		Switch($ID){
			LPAV { $Blob.Version = $Data }
			ACCT {
				Write-Debug "BEGIN ACCOUT DECODE"
				$Account = @{}
				$Schema.Account.Fields.Keys | ForEach {
					Write-Debug "Field: $_"
					$Account[$_] = Read-Item -Blob $Data -Index $ItemIndex
					'Returned length: {0}' -f $Account[$_].Length | Write-Debug
					$ItemIndex += $Account[$_].length + 4
					Write-Debug "End Field $_"
				}

				$Blob.Accounts += [PSCustomObject] $Account
				Write-Debug "END ACCOUNT DECODE"
			}
			SHAR {
				Write-Debug "BEGIN SHARE DECODE"
				$Folder = @{}
				$Schema.SharedFolder.Fields.Keys | ForEach {
					Write-Debug "Field: $_"
					$Folder[$_] = Read-Item -Blob $Data -Index $ItemIndex
					'Returned length: {0}' -f $Folder[$_].Length | Write-Debug
					$ItemIndex += $Folder[$_].length + 4
					Write-Debug "End Field $_"
				}

				If(!$Folder.AESFolderKey -or !$Folder.RSAEncryptedFolderKey){
					'Share key not found for ID: {0}' -f $Folder.ID | Write-Warning
				}

				If($Folder.AESFolderKey){
					$Folder.Key = $Folder.AESFolderKey |
						ConvertFrom-LPEncryptedString |
						ConvertFrom-Hex
				}
				Else{
					$RSA = [RSACryptoServiceProvider]::New()
					$RSA.ImportParameters($Script:Session.Key)
					$Folder.Key = (
						RSA.Decrypt(
							($Folder.RSAEncryptedFolderKey | ConvertFrom-Hex)
						)
					) -join '' | ConvertFrom-Hex
				}

				$Blob.Folders += [PSCustomObject] $Folder
				Write-Debug "END SHARE DECODE"
			}
			Default {
				If($Blob.ContainsKey($ID)){ $Blob[$ID] += $Data }
				Else{ $Blob[$ID] = @($Data) }
			}
		}
	}
	

	$Script:Blob = [PSCustomObject] $Script:Blob
	# If($PSBoundParameters.Debug){
		Write-Output $Script:Blob
	# }
	
	Write-Verbose 'Decrypting account names'
 	$Script:Blob.Accounts | Where { $_.Name } | ForEach {
		$_.Name = ConvertFrom-LPEncryptedString $_.Name
	}


}



Function Get-Account {
	<#
	.SYNOPSIS
	Returns one or more Lastpass accounts/sites
	
	.DESCRIPTION
	Long description
	
	.PARAMETER Name
	The name of the account to return
	
	.EXAMPLE
	Get-Account
	Returns a list of all account IDs and names
	
	.EXAMPLE
	Get-Account -Name 'Email'
	Returns all accounts named 'Email'
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name
	)
	PROCESS {
		If($Name){ $Name | Get-Item -Type Account }
		Else{ Get-Item -Type Account }
	}
}



Function Set-Account {
	<#
	.SYNOPSIS
	Updates a Lastpass Account
	
	.DESCRIPTION
	Sets the properties of a Lastpass account.
	Does a full overwrite (ie. any parameters not included will be
	deleted if they existed as part of the account previously) 
	
	.PARAMETER ID
	The ID of the account

	.PARAMETER Name
	The name of the account

	.PARAMETER Folder
	The directory path that contains the account

	.PARAMETER URL
	The URL of the account

	.PARAMETER Username
	The username of the account

	.PARAMETER Password
	The password of the account

	.PARAMETER Notes
	The notes tied to the account

	.PARAMETER PasswordProtect
	Whether to require a password reprompt to access the account
	
	.PARAMETER Favorite
	Whether the account is marked as a favorite

	.PARAMETER AutoLogin
	If set, the Lastpass browser plugin will automatically 
	fill and submit the login on the account's website
	
	.PARAMETER DisableAutofill
	If set, the Lastpass browser plugin will not autofill the account on the website

	.EXAMPLE
	Set-Account -ID 10248 -Name 'NewName'
	Sets the account with ID 10248 to have the name 'NewName'.
	Note that any username, password, notes, or other properties of the account will be overwritten.
	
	.EXAMPLE
	Get-Account 'Email' | Set-Account -PasswordProtect
	Gets the account named 'Email', and passes it to Set-Account to update the account to require
	a password to access. Passing in an account object will include all of the existing properties,
	so Set-Account will effectively perform an update, only overwriting the parameters explicitly
	passed in.	
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $ID,

		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name,
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Folder,

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $URL,

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Username,		
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Password,
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Notes,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $PasswordProtect,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $Favorite,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $AutoLogin,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $DisableAutofill
	)
	
	Set-Item @PSBoundParameters
	
}



Function Get-Note {
	<#
	.SYNOPSIS
	Returns Lastpass Notes

	.DESCRIPTION
	Parses and decrypts Lastpass Notes.
	Returns a list of all notes if no name is specified, or specific notes if the name is specified.
	Supports password protection.

	.PARAMETER Name
	The name of the note(s) to retrieve. If no name is specified, all notes are returned.

	.EXAMPLE
	Get-Note
	Returns a list of all notes in the Lastpass account.
	The returned objects do not have decrypted content.

	.EXAMPLE
	Get-Note 'Bank PIN'
	Returns all notes called 'Bank PIN', prompting for the password if the note is password protected.
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name
	)
	
	$Param = @{ Type = 'Note' }
	If($Name){ $Param.Name = $Name }
	Get-Item @Param
}



Function Set-Note {
	<#
	.SYNOPSIS
	Updates a Lastpass Note
	
	.DESCRIPTION
	Sets the properties of a Lastpass note.
	Does a full overwrite (ie. any parameters not included will be
	deleted if they existed as part of the note previously) 
	
	.PARAMETER ID
	The ID of the note

	.PARAMETER Name
	The name of the note

	.PARAMETER Folder
	The directory path that contains the note

	.PARAMETER Content
	The content of the note

	.PARAMETER PasswordProtect
	Whether to require a password reprompt to access the note
	
	.PARAMETER Favorite
	Whether the note is marked as a favorite

	.EXAMPLE
	Set-Note -ID 10248 -Name 'NewName'
	Sets the note with ID 10248 to have the name 'NewName'.
	Note that any note content, folder, or other properties of the note will be overwritten.
	
	.EXAMPLE
	Get-Note 'SecretCrush' | Set-Note -PasswordProtect
	Gets the note named 'SecretCrush', and passes it to Set-Note to update the note to require
	a password to access. Passing in a note object will include all of the existing properties,
	so Set-Note will effectively perform an update, only overwriting the parameters explicitly
	passed in.	
	#>

	[CmdletBinding()]
	Param(
		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $ID,

		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name,
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Folder,
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Content,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $PasswordProtect,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $Favorite
	)
	
	Set-Item -SecureNote @PSBoundParameters
	
}

<#
New-Account {}


Remove-Account {}


New-Note {}


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



Function Get-Item {

	<#
	.SYNOPSIS
	Returns one or more Lastpass items
	
	.DESCRIPTION
	Returns one or more Lastpass accounts or secure notes
	
	.PARAMETER Name
	The name of the item to return.
	If no name is provided, Get-Item returns all items

	.PARAMETER Type
	The type of item to return
	Acceptable values are: Account, Note, or All
	
	.EXAMPLE
	Get-Account
	Returns a list of all account IDs and names
	
	.EXAMPLE
	Get-Account -Name 'Email'
	Returns all accounts named 'Email'
	
	#>
	[CmdletBinding()]
	Param(
		[Parameter(
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name,

		[ValidateSet('Account', 'Note', 'All')]
		[String] $Type = 'All'
	)
	PROCESS {
		If($Name){
			$Script:Blob.Accounts.Account |
				Where {
					$_.Name -eq $Name -and
					($Type -eq 'All' -or
					!!([Int] $_.SN) -eq ($Type -eq 'Note'))
				} | ForEach {
					If(!!([Int] $_.PWProtect) -and $PasswordPrompt -lt (
								[DateTime]::Now.Subtract($PasswordTimeout))){
						# TODO: Should this loop? Possibly for a set number of retries?
						$Password = Read-Host -AsSecureString 'Please confirm your password'
						$Credential = [PSCredential]::New($Script:Session.Username, $Password)
						$Key = New-Key -Credential $Credential -Iterations $Script:Session.Iterations

						$Param = @{
							ReferenceObject	 = $Script:Session.Key
							DifferenceObject = $Key
							SyncWindow		 = 0
						}
						If(Compare-Object @Param){ Throw 'Password confirmation failed' }
						$Script:PasswordPrompt = [DateTime]::Now
					}

					If(!([Int]$_.SN)){
						[PSCustomObject] @{
							ID				= $_.ID
							Name			= $_.Name
							URL				= ($_.URL -split '([a-f0-9]{2})' | ForEach {
													If($_){ [Char][Convert]::ToByte($_,16) }
												}) -join ''
							Folder			= $_.Group | ConvertFrom-LPEncryptedString
							Username		= $_.Username | ConvertFrom-LPEncryptedString 
							Credential		= [PSCredential]::New(
												($_.Login.U | ConvertFrom-LPEncryptedString),
												($_.Login.P | ConvertFrom-LPEncryptedString | ForEach {
														If($_){ $_ | ConvertTo-SecureString -AsPlainText -Force }
														Else { [SecureString]::New() }
													})
												) 
							Notes			= $_.Extra | ConvertFrom-LPEncryptedString 
							Favorite		= !!([Int] $_.Fav)
							Bookmark		= !!([Int] $_.IsBookmark)
							PasswordProtect = !!([Int] $_.PWProtect)
							LaunchCount		= [Int] $_.Launch_Count
							LastModified	= $Epoch.AddSeconds($_.Last_Modified)
							LastAccessed	= [DateTime]::Now
							
						} | Add-Member -Passthru -MemberType ScriptProperty -Name Password -Value {
							$This.Credential.GetNetworkCredential().Password
						} | Set-ObjectMetadata 'Account' $Script:Schema.Account.DefaultFields |
							Write-Output
					}
					Else{
						[PSCustomObject] @{
							ID				= $_.ID
							Name			= $_.Name
							Content			= $_.Extra | ConvertFrom-LPEncryptedString
							Folder			= $_.Group | ConvertFrom-LPEncryptedString
							Favorite		= !!([Int] $_.Fav)
							PasswordProtect	= !!([Int] $_.PWProtect)
							LastModified	= $Epoch.AddSeconds($_.Last_Modified)
							LastAccessed	= [DateTime]::Now
							# NoteType
						} | Set-ObjectMetadata -TypeName 'Note' -DefaultDisplayProperties $Script:Schema.Note.DefaultFields |
							Write-Output
					}
				}
		}
		Else{
			$Script:Blob.Accounts.Account |
				Where {
					$_.Name -and 
					($Type -eq 'All' -or 
						!!([Int] $_.SN) -eq ($Type -eq 'Note'))
				} |
				Select ID, Name | 
				Write-Output
		}
	}	
}



Function Set-Item {
	<#
	.SYNOPSIS
	Updates a Lastpass Item
	
	.DESCRIPTION
	Sets the properties of a Lastpass account, secure note, or folder.
	All of these items are saved as account objects in Lastpass.
	Does a full overwrite (ie. any parameters not included will be
	deleted if they existed as part of the item previously)
	
	.PARAMETER ID
	The ID of the item

	.PARAMETER Name
	The name of the item

	.PARAMETER SecureNote
	If set, the item is a secure note

	.PARAMETER Folder
	The directory path that contains the item

	.PARAMETER URL
	The URL of the item,
	If secure note, this is set to 'http://sn'

	.PARAMETER Username
	The username of the account

	.PARAMETER Password
	The password of the account

	.PARAMETER Notes
	The notes tied to the item

	.PARAMETER PasswordProtect
	Whether to require a password reprompt to access the item
	
	.PARAMETER Favorite
	Whether the item is marked as a favorite

	.PARAMETER AutoLogin
	If set, the Lastpass browser plugin will automatically 
	fill and submit the login on the account's website
	
	.PARAMETER DisableAutofill
	If set, the Lastpass browser plugin will not autofill the account on the website
	
	.EXAMPLE
	Set-Item -ID 10248 -Name 'NewName'
	Sets the account with ID 10248 to have the name 'NewName'.
	Note that any username, password, notes, or other properties of the account will be overwritten.
	
	.EXAMPLE
	Get-Account 'Email' | Set-Item -PasswordProtect
	Gets the account named 'Email', and passes it to Set-Item to update the account to require
	a password to access. Passing in an account object will include all of the existing properties,
	so Set-Item will effectively perform an update, only overwriting the parameters explicitly
	passed in.	
	#>
	
	[CmdletBinding(DefaultParameterSetName='Account')]
	Param(
		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $ID,

		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name,

		[Parameter(
			ParameterSetName='SecureNote',
			ValueFromPipelineByPropertyName
		)]
		[Switch] $SecureNote,
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Folder,

		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[String] $URL,

		[Parameter(
			ParameterSetName='Account', 
			ValueFromPipelineByPropertyName
		)]
		[String] $Username,

		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[String] $Password,	
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[Alias('Content','Extra')]
		[String] $Notes,
		
		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $PasswordProtect,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $Favorite,
		
		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[Switch] $AutoLogin,

		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[Switch] $DisableAutofill		

	)

	BEGIN {
		$Param = @{
			URI			= 'https://lastpass.com/show_website.php'
			Method		= 'POST'
			WebSession	= $Script:WebSession
		}

		$BodyBase = @{
			extjs	= 1
			token	= $Script:Session.Token
			method	= 'cli'
		}

	}

	PROCESS {
		If($SecureNote){ $URL = 'http://sn' }
		
		$Body = @{
			aid		 = $ID
			name	 = $Name | ConvertTo-LPEncryptedString
			grouping = $Folder | ConvertTo-LPEncryptedString
			url		 = ([Byte[]][Char[]] $URL | ForEach { "{0:x2}" -f $_ }) -join ''
			extra	 = $Notes | ConvertTo-LPEncryptedString
			<#
			folder = 'user'		#, 'none', or name of default folder
			#localupdate = 1	# ?
			#ajax = 1			# ?
			#source = 'vault'	# ?
			#urid = 0			# ?
			#auto = 1			# ?
			#iid = ''			# ?
			#>
		}

		If(!$SecureNote){
			$Body.username = $Username | ConvertTo-LPEncryptedString
			$Body.password = $Password | ConvertTo-LPEncryptedString
			
			If($AutoLogin){ $Body.autologin = 'on' }
			If($DisableAutofill){ $Body.never_autofill = 'on' }
		}

		If($PasswordProtect){ $Body.pwprotect = 'on' }
		If($Favorite){ $Body.fav = 'on' }
		
		"Request Parameters:`n{0}" -f ($Body | Out-String) | Write-Debug
		$Response = Invoke-RestMethod @Param -Body ($BodyBase + $Body)
		$Response.OuterXML | Out-String | Write-Debug
		
		Switch($Response.XMLResponse.Result.Msg){
			'AccountCreated' {

			}
			'AccountUpdated' {

				Break
			}
			Default { Throw "Failed to update $Name" }
		}
	}

	END { Sync-Lastpass }
}



Function New-Key {
	<#
	.SYNOPSIS
	Generates a decryption key for a Lastpass account
		
	.PARAMETER Credential
	The Lastpass account credential

	.PARAMETER Iterations
	The number of hashing iterations
		
	.EXAMPLE
	New-Key -Credential $Credential -Iterations $Iterations
	Creates a new Lastpass decryption key using the username and password in the $Credential
	variable, and the number of iterations in the $Iterations variable
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[PSCredential] $Credential,

		[Parameter(Mandatory)]
		[Int] $Iterations
	)

	$EncodedUsername = [Byte[]][Char[]] $Credential.Username.ToLower()
	$EncodedPassword = [Byte[]][Char[]] $Credential.GetNetworkCredential().Password

	$Key = Switch($Iterations){
		1 {
			[SHA256Managed]::New().ComputeHash(
				$EncodedUsername + $EncodedPassword
			)
			Break
		}
		{$_ -gt 1} {
			[Rfc2898DeriveBytes]::New(
				$EncodedPassword, 
				$EncodedUsername, 
				$Iterations, 
				[HashAlgorithmName]::SHA256
			).GetBytes(32)
			Break
		}
		Default { Throw "Invalid Iteration value: '$Iterations'" }
	}
	Write-Debug "Key: $Key"
	Write-Output $Key
}



Function New-LoginHash {
	<#
	.SYNOPSIS
	Generates a hash value used for logging in to Lastpass
		
	.PARAMETER Key
	The decryption key for the Lastpass account

	.PARAMETER Credential
	The Lastpass account credential

	.PARAMETER Iterations
	The number of hashing iterations
	
	.EXAMPLE
	New-LoginHash -Key $Key -Credential $Credential -Iterations $Iterations
	Generates a new hash value used for logging in to Lastpass using the key in the $Key variable,
	the username and password in the $Credential variable, and the number of iterations in the
	$Iterations variable
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[Byte[]] $Key,

		[Parameter(Mandatory)]
		[PSCredential] $Credential,

		[Parameter(Mandatory)]
		[Int] $Iterations
	)
	$Password = $Credential.GetNetworkCredential().Password
	$Hash = Switch($Iterations){
			1 {
				[SHA256Managed]::New().ComputeHash(
					[Byte[]][Char[]] (
						(($Key | ForEach { "{0:x2}" -f $_ }) -join '') + 
						$Password
					)
				)
				Break
			}
			{$_ -gt 1} {
				[Rfc2898DeriveBytes]::New(
					$Key,
					([Byte[]][Char[]] $Password),
					1,
					[HashAlgorithmName]::SHA256
				).GetBytes(32)
				Break
			}
			Default { Throw "Invalid Iteration value: '$Iterations'" }
		}
	$Hash = ($Hash | ForEach { "{0:x2}" -f $_ }) -join ''
	
	Write-Debug "Hash: $Hash"
	Write-Output $Hash
}


Function Read-Item {
	<#
	.SYNOPSIS
	 Short description
	
	.DESCRIPTION
	Long description
	
	.PARAMETER ParameterName
	Parameter description
	
	.EXAMPLE
	Read-Item
	
	.EXAMPLE
	Read-Item
	#>
	
	[CmdletBinding()]
	Param(
		[String] $Blob,
		[Int] $Index
	)
	# Try{
		Write-Debug "Read-Item start index: $Index"
		#"Blob Snippet: {0}" -f ($Blob[$Index..($Index+50)] -join '') | Write-Debug
	

		$Size = $Blob[($Index)..($Index+=3)]
		#Write-Host $Size
		#[BitConverter]::ToUInt32($Size,0) | Write-Host
		If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
		#Write-Host $Size
		$Size = [BitConverter]::ToUInt32($Size,0)
		Write-Debug "Size: $Size"
		If($Size){
			$Data = $Blob[($Index+=1)..(($Index+=$Size)-1)] -join ''
			Write-Debug "Data: $Data"
			Write-Output $Data
		}
	# }
	# Catch{
	# 	Throw 'Hit error'
	# }
	
}


Function Read-ASN1Item {
	<#
	.SYNOPSIS
	Parses an ASN1 encoded byte array
	
	.DESCRIPTION
	Lastpass' private key is sent using an ASN1 encoded byte array.
	This function does basic parsing of an ASN1 encoded data structure.
	
	.PARAMETER ParameterName
	Parameter description
	
	.EXAMPLE
	Read-ASN1
	
	.EXAMPLE
	Read-ASN1
	#>
	
	[CmdletBinding()]
	Param(
		[Byte[]] $Blob,
		[Int] $Index = 0
	)
	$Object = @{
		Type = Switch($Blob[$Index] -band 0x1F){
			2		{ 'Integer' }
			4		{ 'Bytes' }
			5		{ 'Null' }
			16		{ 'Sequence' }
			Default { Return $Null }
		}
	}
	$Size = $Blob[($Index+=1)]
	If($Size -band 0x80 -ne 0){
		$Size = 0
		$Length = $Blob[$Index] -band 0x7F
		0..$Length | ForEach {
			$Size = $Size * 256 + ([Byte] $Blob[($Index+=1)])
		}
	}
	$Object.Value = $Blob[($Index)..($Index+=$Size)]
	$Object.Index = $Index
	Write-Output $Object
}

Function ConvertFrom-LPEncryptedString {
	
	<#
	.SYNOPSIS
	Decrypts Lastpass encrypted strings
	
	.DESCRIPTION
	Decrypts strings encrypted for Lastpass server communication
	Supports CBC and ECB encryption

	.PARAMETER Value
	The encrypted Lastpass string to decrypt
	
	.EXAMPLE
	ConvertFrom-LPEncryptedString -Value '!lks;jf90s|fsafj9#IOj893fj'
	Decrypts the Lastpass encrypted input string
	
	.EXAMPLE
	$EncryptedAccounts.Name | ConvertFrom-LPEncryptedString
	Decrypts the names of the accounts in the $EncryptedAccounts variable
	#>
	
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
		If(!$Session.Key){ Throw 'Key not found. Please login using Connect-Lastpass.' }
		$AES = [AesManaged]::New()
		$AES.KeySize = 256
		$AES.Key = $Session.Key
	}
	
	PROCESS {
		$Value | ForEach {
			If($_[0] -eq '!' -and
			$_.Length -gt 32 -and
			$_.Length % 16 -eq 1){
			#('!{0}|{1}' -f $IV, $Data).Length % 16 -eq 1){
				Write-Debug 'CBC'
				#TODO: Test whether Base64 conversion is necessary
				$AES.Mode = [CipherMode]::CBC
				#$Data = [Convert]::FromBase64String($_[26..($_.Length-1)])
				$Data = $_[17..($_.Length-1)]
				#$AES.IV = [Convert]::FromBase64String($_[1..24])
				$AES.IV = $_[1..16]
			}	
			Else{
				Write-Debug 'ECB'
				$AES.Mode = [CipherMode]::ECB
				#$Data = [Convert]::FromBase64String($_)
				$Data = [char[]] $_
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



Function ConvertTo-LPEncryptedString {
	
	<#
	.SYNOPSIS
	Encrypts Lastpass encoded strings
	
	.DESCRIPTION
	Encrypts strings for communication with Lastpass and storage
	Uses CBC encryption, generating a new random CBC IV.

	.PARAMETER Value
	The string to encrypt
	
	.EXAMPLE
	ConvertTo-LPEncryptedString -Value 'SecretText'
	Encrypts the input string 'SecretText
	
	.EXAMPLE
	$DecryptedAccounts.Username | ConvertTo-LPEncryptedString
	Encrypts the names of the accounts in the $DecryptedAccounts variable
	#>
	
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
		If(!$Session.Key){ Throw 'Key not found. Please login using Connect-Lastpass.' }
		$AES = [AesManaged]::New()
		$AES.KeySize = 256
		$AES.Key = $Session.Key
		$AES.Mode = [CipherMode]::CBC
	}
	
	PROCESS {
		$Value | ForEach {
			$AES.GenerateIV()
			$Encryptor = $AES.CreateEncryptor()
			
			$EncryptedValue = $Encryptor.TransformFinalBlock([Byte[]][Char[]] $_, 0, $_.Length)
			
			'!{0}|{1}' -f @(
				[Convert]::ToBase64String($AES.IV),
				[Convert]::ToBase64String($EncryptedValue)
			) | Write-Output
		}
	}
}



Function ConvertFrom-Hex {
	<#
	.SYNOPSIS
	 Short description
	
	.DESCRIPTION
	Long description
	
	.PARAMETER ParameterName
	Parameter description
	
	.EXAMPLE
	ConvertFrom-Hex
	
	.EXAMPLE
	ConvertFrom-Hex
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(
			Mandatory,
			ValueFromPipeline, 
			ValueFromPipelineByPropertyName,
			Position = 0
		)]
		[AllowEmptyString()]
		[String[]] $Value
	)
	
	$Value | ForEach {
		($_ -split '([a-f0-9]{2})' | ForEach {
			If($_){ [Char][Convert]::ToByte($_,16) }
		}) -join ''
	}
	
}


Function Set-ObjectMetadata {
	<#
	.SYNOPSIS
	Sets object type name and default display properties
	
	.PARAMETER TypeName
	The PSTypeName to assign to the object
	
	.PARAMETER DefaultDisplayProperties
	The properties to show for default output of the object
	
	.PARAMETER InputObject
	The object to set the type name and default display properties
	
	.EXAMPLE
	Set-ObjectMetadata $Object 'Type.Name' 'ID','Name','Value'
	Sets the PSTypeName to 'Type.Name' and the default display
	properties to the ID, name, and value properties
	
	.EXAMPLE
	$Object | Set-Object -TypeName 'Type.Name' -DefaultDisplayProperties @('ID','User')
	Sets the PSTypeName to 'Type.Name' and the default display
	properties to the ID and user properties. This example shows
	passing the object through the pipeline
	#>
	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[String] $TypeName,
		
		[Parameter(Mandatory)]
		[String[]] $DefaultDisplayProperties,
		
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject] $InputObject
		
	)
	
	$InputObject.PSTypeNames[0] = "Lastpass.$TypeName"

	$Param = @{
		MemberType	= 'MemberSet'
		Name		= 'PSStandardMembers'
		Passthru	= $True
		Value		= [Management.Automation.PSPropertySet]::New(
							'DefaultDisplayPropertySet',
							[String[]] $DefaultDisplayProperties
						)
	}

	$InputObject | Add-Member @Param
	
}



#FIXME! Remove; for debugging purposes only
Function Get-Session {
	Return [PSCustomObject] @{
		WebSession = $WebSession
		Session = $Session
	}
}


Function Set-Session {
	Param(
		[PSCustomObject] $Session
	)

	$Script:WebSession = $Session.WebSession
	$Script:Session = $Session.Session

}


# Export-ModuleMember -Function @(
# 	'Connect-Lastpass'
# 	'Sync-Lastpass'
# 	'Get-Account'
# 	'Set-Account'
# 	'Get-Note'
# )