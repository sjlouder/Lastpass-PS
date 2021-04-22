# Lastpass Powershell Module
# Copyright (C) 2020 Steven Loudermilk
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

Param(
	[ValidateScript({
		$Schema = @{
			ExportWriteCmdlets = 'Boolean'
			Debug = 'Boolean'
		}
		$_.GetEnumerator() | ForEach {
			If($_.Key -notin $Schema.Keys){
				Throw "Unknown module parameter: $($_.Key)"
			}
			If($_.Value -isnot $Schema[$_.Key]){
				Throw "Parameter '$($_.Key)' should be of type: [$($Schema[$_.Key])]"
			}
		}
		Return $True
	})]
	[HashTable] $ModuleParameters = @{}
)

$Script:Interactive = [Environment]::UserInteractive -and
	!([Environment]::GetCommandLineArgs() -like '-NonI*')
$Script:Epoch = [DateTime] '1970-01-01 00:00:00'
$Script:Schema = @{

	Account = @{
		Fields = [Ordered] @{
			ID = 'String'
			Name = 'Encrypted'
			Folder = 'Encrypted'
			URL = 'Hex'
			Notes = 'Encrypted'
			Favorite = 'Boolean'
			SharedFromAID = 'String' #?
			Username = 'Encrypted'
			Password = 'Encrypted'
			PasswordProtect = 'Boolean'
			GeneratedPassword = 'Boolean' #?
			SecureNote = 'Boolean' #?
			LastAccessed = 'Date'
			AutoLogin = 'Boolean' #?
			NeverAutofill = 'Boolean' #?
			RealmData = 'String' #?
			FIID = 'Skip' #?
			CustomJS = 'Skip' #?
			SubmitID = 'Skip' #?
			CaptchaID = 'Skip' #?
			URID = 'Skip' #?
			BasicAuth = 'Boolean' #?
			Method = 'Skip' #?
			Action = 'Skip'
			GroupID = 'String' #?
			Deleted = 'Boolean' #?
			AttachmentKey = 'String'
			AttachmentPresent = 'Boolean'
			IndividualShare = 'Boolean' #?
			NoteType = 'String' #?
			NoAlert = 'String' #?
			LastModifiedGMT = 'Date' #?
			HasBeenShared = 'Boolean' #?
			LastPasswordChange = 'Date' #?
			DateCreated = 'Date' #?
			Vulnerable = 'String' # JSON of exposure info
		}
		DefaultFields = @(
			'Name'
			'Username'
			'Folder'
			'Favorite'
		)
	}
	SecureNote = @{
		Fields = @(
			'ID'
			'Name'
			'Folder'
			'NoteType'
			'Notes'
			'AttachmentPresent'
			'AttachmentKey'
			'PasswordProtect'
			'Favorite'
			'Deleted'
			'HasBeenShared'
			'FIID'
			'DateCreated'
			'LastAccessed'
			'LastModifiedGMT'
			'LastPasswordChange'
			'ShareID'
		)
		DefaultFields = @(
			'Name'
			'Folder'
			'Favorite'
		)
		Types = @{
			Address				= "Address"
			Bank				= "Bank Account"
			Credit				= "Credit Card"
			Database			= "Database"
			DriversLicense		= "Driver's License"
			Email				= "Email Account"
			Generic				= "Generic"
			HealthInsurance		= "Health Insurance"
			IM					= "Instant Messenger"
			Insurance			= "Insurance"
			Membership			= "Membership"
			Passport			= "Passport"
			Server				= "Server"
			SSN					= "Social Security"
			SoftwareLicense		= "Software License"
			SSHKey				= "SSH Key"
			Wifi				= "Wi-Fi Password"
			Custom				= "Custom"
		}
	}
	Folder = @{
		Fields = @(
			'ID'
			'Name'
			'FIID'
			'DateCreated'
			'LastAccessed'
			'LastModifiedGMT'
			'LastPasswordChange'
			'ShareID'
		)
		DefaultFields = @(
			'Name'
			'LastModifiedGMT'
			'LastPasswordChange'
		)
	}
	SharedFolder = @{
		Fields = [Ordered] @{
			ID = 'String'
			RSAEncryptedFolderKey = 'Hex'
			Name = 'String'
			ReadOnly = 'Boolean'
			Give = 'Boolean' #?
			AESFolderKey = 'String'
		}
		DefaultFields = @(
			'Name'
			'ReadOnly'
		)
	}
	FormField = @{
		Fields = [Ordered] @{
			Name = 'String'
			Type = 'String'
			Value = 'Other'
			Checked = 'Boolean'
		}
		DefaultFields = @(
			'Name'
			'Type'
			'Value'
			'Checked'
		)
	}
	Attachment = @{
		Fields = [Ordered] @{
			ID = 'String'
			Parent = 'String'
			MIMEType = 'String'
			StorageKey = 'String'
			Size = 'String'
			FileName = 'Encrypted'
		}
		DefaultFields = @(
			'FileName'
			'MIMEType'
			'Size'
		)
	}
}

$Schema.GetEnumerator() | ForEach {
	$Param = @{
		TypeName = "Lastpass.$($_.Key)"
		DefaultDisplayPropertySet = $_.Value.DefaultFields
		Force = $True
	}
	Update-TypeData @Param
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

	.PARAMETER SkipSync
	If specified, the sync of account data on successful login will be skipped.

	.EXAMPLE
	Connect-Lastpass -Credential (Get-Credential)

	Logs in to Lastpass, prompting for the username and password

	.EXAMPLE
	Connect-Lastpass -Credential $Credential -OneTimePassword 158320

	Logs in to Lastpass, with the credentials saved in the $Credential
	variable. Includes the one time password.
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSAvoidUsingPlainTextForPassword',
		'OneTimePassword',
		Justification='One time password can be sent in cleartext'
	)]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSAvoidUsingWriteHost', '',
		Justification = 'Message is for user interaction,
			code checks whether there is an interactive prompt,
			and it is designed to use -noNewLine'
	)]
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[PSCredential] $Credential,

		[String] $OneTimePassword,
		[Switch] $SkipSync
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
								$NextInput = [Console]::ReadKey($True)
								Write-Debug ("Key: {0} {1}" -f $NextInput.Key, ($NextInput.Key -eq 'Enter'))
								If( $NextInput.Key -eq 'Enter' ){
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
								$OneTimePassword += $NextInput.KeyChar
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
		UID			= $Response.OK.UID
		SessionID	= $Response.OK.SessionID
		Token		= $Response.OK.Token
		PrivateKey	= [RSAParameters]::New()
		Iterations	= $Response.OK.Iterations
		Username	= $Response.OK.LPUsername
		Key			= $Key
	}

	If($Response.OK.PrivateKeyEnc){
		If($Response.OK.PrivateKeyEnc[0] -eq '!'){
			Write-Debug 'Version 2 private key encoding'
			$DecryptedKey = [Convert]::FromBase64String($Response.OK.PrivateKeyEnc) -join '' |
				ConvertFrom-LPEncryptedData
		}
		Else{
			Write-Debug 'Version 1 private key encoding'
			$DecryptedKey = '!{0}{1}' -f @(
				([char[]] $S.Session.Key -join ''),
				(([Char[]] ($Response.OK.PrivateKeyEnc | ConvertFrom-Hex)) -join '')
			) | ConvertFrom-LPEncryptedData
		}

		If(!$DecryptedKey){
			Write-Warning 'Failed to decrypt private key'
		}
		ElseIf($DecryptedKey -notmatch '^.*ey<(.*)>LastPassPrivateKey$'){
			Write-Warning 'Failed to decode decrypted private key'
		}
		Else{
			$ASN1 = $Matches[1] | ConvertFrom-Hex
			Write-Debug "ASN1 Length: $($ASN1.Length)"
			# This is a ASN.1 encoding, do basic parsing
			$Sequence = (Read-ASN1Item -Blob $ASN1).Value
			Write-Debug "Sequence Parsed. Length: $($Sequence.Length)"
			$Index = 0
			1..2 | ForEach { Write-Debug "$_"; $Index = (Read-ASN1Item -Blob $Sequence -Index $Index).Index }
			Write-Debug "Sequence 2 Index: $Index"
			$Sequence2 = (Read-ASN1Item -Blob $Sequence -Index $Index).Value
			Write-Debug "Sequence 2 Parsed. Length: $($Sequence2.Length)"

			$Sequence3 = (Read-ASN1Item -Blob $Sequence2).Value
			Write-Debug "Sequence 3 Parsed. Length: $($Sequence3.Length)"

			$Index = (Read-ASN1Item -Blob $Sequence3).Index

			# RSAParameters is a struct, so have to create a populated
			# copy and then assign the entire struct at once.
			$Parameters = @{}

			'Modulus',
			'Exponent',
			'D',
			'P',
			'Q',
			'DP',
			'DQ',
			'InverseQ' | ForEach {
				Write-Debug $_
				$ASN1Item = Read-ASN1Item -Blob $Sequence3 -Index $Index
				$ASN1Item.Value -is [Array] | Write-Debug
				$Index = $ASN1Item.Index
				$ByteIndex = 0
				# This is hacky, but I can't get it to treat a single byte value as an array
				If($ASN1Item.Value -is [Array]){
					While($ASN1Item.Value[$ByteIndex] -eq 0){
						write-debug 'skipping 0';
						$ByteIndex++
					}
					"Indices: {0}, {1}" -f $ByteIndex, ($ASN1Item.Value.Length -1) | Write-Debug
					$Parameters[$_] = $ASN1Item.Value[$ByteIndex..($ASN1Item.Value.Length -1)]
				}
				Else{
					$Parameters[$_] = $ASN1Item.Value
				}
			}

			$Parameters | Out-String | Write-Debug

			# New-Object seems to be required to set struct members at creation
			$Session.PrivateKey = New-Object RSAParameters -Property $Parameters
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

	If(!$SkipSync){ Sync-Lastpass | Out-Null }

	If($PSBoundParameters.Debug){ Return $Response }

	[PSCustomObject] @{
		Email = $Credential.Username
		SessionID = $Script:Session.SessionID
	} | Write-Output

}



Function Disconnect-Lastpass {
	<#
	.SYNOPSIS
	Ends Lastpass session

	.DESCRIPTION
	Calls the logout API and clears the local session
	Does not currently support saving local copy of vault

	.EXAMPLE
	Disconnect-Lastpass

	Ends the current Lastpass session

	#>

	[CmdletBinding()]
	Param()

	$Param = @{
		Method = 'Post'
		URI = 'https://lastpass.com/logout.php'
		WebSession = $Script:WebSession
		Body = @{
			method = 'cli'
			noredirect = '1'
			token = $Session.Token
		}
	}
	Invoke-RestMethod @Param | Out-Null

	$Script:Session = $Null
	$Script:Blob = $Null
	$Script:WebSession = $Null
	$Script:PasswordTimeout = New-Timespan
	$Script:PasswordPrompt = $Null
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

	If(!$Script:Session){ Throw 'User session not found. Log in with Connect-Lastpass' }
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
	If($PSBoundParameters.Debug){ Return $Response }
	#"Response:`n{0}" -f $Response | Write-Debug
	# Return ([char[]][Convert]::FromBase64String($Response)) -join ''
	$Response = [Byte[]][Char[]] $Response

	#TODO: Cleanup debug output.
	#	Wrap parse in try/catch and provide info in catch error
	Write-Verbose 'Parsing data'
	$Index = 0
	$Script:Blob = @{
		Metadata		= @{}
		Accounts		= [Collections.ArrayList]::New()
		SecureNotes		= [Collections.ArrayList]::New()
		Folders			= [Collections.ArrayList]::New()
		SharedFolders	= [Collections.ArrayList]::New()
}
	While($Index -lt ($Response.Length-8)){
		$Type = ([Char[]] $Response[$Index..(($Index+=3))]) -join ''
		$PSCmdlet.WriteDebug("Type: $Type")
		$PSCmdlet.WriteDebug("Index: $Index")

		$Size = $Response[($Index+=1)..($Index+=3)]
		If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
		$Size = [BitConverter]::ToUInt32($Size,0)
		$PSCmdlet.WriteDebug("Size: $Size")

		If($Size){
			$Data = $Response[($Index+=1)..(($Index+=$Size)-1)]
			$PSCmdlet.WriteDebug("Data: $Data")
			$PSCmdlet.WriteDebug("DataSize: $($Data.Length)")
		}

		$PSCmdlet.WriteDebug("After index: $Index")

		If(!$Blob.Metadata[$Type]){ $Blob.Metadata[$Type] = 1}
		Else{ $Blob.Metadata[$Type] += 1 }

		If($Type -eq 'ENDM' -and (([Char[]] $Data) -join '') -eq 'OK'){ Break }

		$ItemIndex = 0
		$Param = @{}
		Switch($Type){
			LPAV { $Blob.Version = [Char[]] $Data -join '' }
			ACCT {
				$PSCmdlet.WriteDebug("BEGIN ACCOUNT DECODE")
				$Account = @{ PSTypeName = 'Lastpass.Account' }
				If($Blob.SharedFolders[-1].Key){ $Param = @{ Key = $Blob.SharedFolders[-1].Key } }
				ForEach($Field in $Schema.Account.Fields.GetEnumerator()) {# | ForEach {
					$PSCmdlet.WriteDebug("Field: $($Field.Key)")

					$Size = $Data[$ItemIndex..($ItemIndex+=3)]
					If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
					$Size = [BitConverter]::ToUInt32($Size,0)
					$PSCmdlet.WriteDebug("Size: $Size")
					If($Size){
						$Item = $Data[($ItemIndex+=1)..(($ItemIndex+=$Size)-1)]
						$PSCmdlet.WriteDebug("Data: $Item")
					}Else{ $Item = $Null; $ItemIndex +=1 }



					# TODO: This switch statement is taking about 65% of the
					# run time on a moderately large dataset (with no shares
					# or attachments). Focal point for future performance
					# improvements
					$Account[$Field.Key] = Switch($Field.Value){
						Encrypted {
							# The name and group are sent encrypted, but are generally needed
							# for organizing and finding the accounts, so they are decrypted here.
							If($Field.Key -in 'Name','Folder'){
								ConvertFrom-LPEncryptedData @Param -Data ([Char[]] $Item -join '' )
							}
							Else{ ConvertTo-LPEncryptedString @Param -Bytes $Item }
						}
						#TODO: See if there are cleaner ways to do these conversions
						Hex		{ [Char[]] (ConvertFrom-Hex ([Char[]] $Item -join '')) -join '' }
						Boolean	{ !!([Int] ([Char[]] $Item -join '')) }
						Date	{ $Epoch.AddSeconds([Char[]] $Item -join '') }
						Default	{ If($Item){[Char[]] $Item -join ''} }
					}
					$PSCmdlet.WriteDebug(("Decoded value: {0}" -f $Account[$Field.Key]))
					$PSCmdlet.WriteDebug("End Field $_")
				}

				If($Account.Folder -in '(none)', ''){ $Account.Folder = $Null }

				If($Blob.SharedFolders[-1]){
					If($Account.Folder){
						$Account.Folder = '{0}\{1}'-f $Blob.SharedFolders[-1].Name, $Account.Folder
					}
					Else{ $Account.Folder = $Blob.SharedFolders[-1].Name }
					$Account.ShareID = $Blob.SharedFolders[-1].ID
				}

				Switch($Account.URL){
					'http://sn' {
						$PSCmdlet.WriteDebug('Item is Secure note')
						$Account.Keys.Where({$_ -notin $Schema.SecureNote.Fields }) |
							ForEach { $Account.Remove($_) }
						$Account.PSTypeName = 'Lastpass.SecureNote'
						If($Account.AttachmentPresent){

							$Account.AttachmentKey = ConvertTo-LPEncryptedString @Param -Bytes (
								[Byte[]] [Char[]] $Account.AttachmentKey
							)
						}
						$Blob.SecureNotes.Add($Account)
					}
					'http://group' {
						$PSCmdlet.WriteDebug('Item is folder')
						$Account.Name = $Account.Folder
						$Account.Keys.Where({$_ -notin $Schema.Folder.Fields}) |
							ForEach { $Account.Remove($_) }
						$Account.PSTypeName = 'Lastpass.Folder'
						$Blob.Folders.Add($Account)
					}
					Default {
						$Blob.Accounts.Add($Account)
					}
				}

				$PSCmdlet.WriteDebug("END ACCOUNT DECODE")
			}
			{$_ -in 'ACFL','ACOF'} {
				$PSCmdlet.WriteDebug('BEGIN FORMFIELD DECODE')
				If(!$Blob.Accounts[-1]){ Throw 'Parse failed. Unable to find account for form fields' }
				If(!$Blob.Accounts[-1].FormFields){ $Blob.Accounts[-1].FormFields = [Collections.ArrayList]::New() } #@() }
				$FormField = [Ordered] @{}

				ForEach ($Field in $Schema.FormField.Fields.Keys){
					$PSCmdlet.WriteDebug("Field: $Field")

					$Size = $Data[$ItemIndex..($ItemIndex+=3)]
					If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
					$Size = [BitConverter]::ToUInt32($Size,0)
					$PSCmdlet.WriteDebug("Size: $Size")
					If($Size){
						$Item = $Data[($ItemIndex+=1)..(($ItemIndex+=$Size)-1)]
						$PSCmdlet.WriteDebug("Data: $Item")
					}Else{ $Item = $Null; $ItemIndex +=1 }


					$FormField[$Field] = Switch($Schema.FormField.Fields[$Field]){
						Boolean { !!([Int] ([Char[]] $Item -join '')) }
						String { If($Item){[Char[]] $Item -join ''} }
						Default { $Item }
					}
					$PSCmdlet.WriteDebug("End Field $_")
				}
				Switch -Regex ($FormField.Type){
					'email|tel|text|password|textarea' {
						$FormField.Value = ConvertTo-LPEncryptedString @Param -Bytes $FormField.Value
					}
					Default { $FormField.Value = [Char[]] $FormField.Value -join '' }
				}

				$Blob.Accounts[-1].FormFields.Add($FormField)
				$PSCmdlet.WriteDebug('END FORMFIELD DECODE')
			}
			ATTA {
				$PSCmdlet.WriteDebug('BEGIN ATTACHMENT DECODE')

				$Attachment = @{ PSTypeName = 'Lastpass.Attachment' }
				$Schema.Attachment.Fields.Keys | ForEach {
					$PSCmdlet.WriteDebug("Field: $_")

					$Size = $Data[$ItemIndex..($ItemIndex+=3)]
					If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
					$Size = [BitConverter]::ToUInt32($Size,0)
					$PSCmdlet.WriteDebug("Size: $Size")
					If($Size){
						$Item = $Data[($ItemIndex+=1)..(($ItemIndex+=$Size)-1)]
						$PSCmdlet.WriteDebug("Data: $Data")
					}Else{ $Item = $Null; $ItemIndex +=1 }


					$Attachment[$_] = Switch($Schema.Attachment.Fields[$_]){
						Encrypted { ConvertTo-LPEncryptedString @Param -Bytes $Item }
						String { If($Item){[Char[]] $Item -join ''} }
					}

					$PSCmdlet.WriteDebug("End Field: $_")
				}
				$SecureNote = $Blob.SecureNotes | Where ID -eq $Attachment.Parent
				If(!$SecureNote){
					"Unable to find Secure Note for attachment {0}`n{1}" -f @(
						$Attachment.ID
						$Attachment | Out-String
					) | Write-Warning
				}
				If(!$SecureNote.Attachments){ $SecureNote.Attachments = [Collections.ArrayList]::New() } #@() }
				$SecureNote.Attachments.Add($Attachment)

				$PSCmdlet.WriteDebug('END ATTACHMENT DECODE')

			}
			SHAR {
				$PSCmdlet.WriteDebug("BEGIN SHARE DECODE")
				$Folder = @{ PSTypeName = 'Lastpass.SharedFolder' }
				$Schema.SharedFolder.Fields.Keys | ForEach {
					$PSCmdlet.WriteDebug("Field: $_")

					$Size = $Data[$ItemIndex..($ItemIndex+=3)]
					If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
					$Size = [BitConverter]::ToUInt32($Size,0)
					$PSCmdlet.WriteDebug("Size: $Size")
					If($Size){
						$Item = $Data[($ItemIndex+=1)..(($ItemIndex+=$Size)-1)]
						$PSCmdlet.WriteDebug("Data: $Data")
					}Else{ $Item = $Null; $ItemIndex +=1 }


					$Folder[$_] = Switch($Schema.SharedFolder.Fields[$_]){
						String	{ If($Item){[Char[]] $Item -join ''} }
						Boolean	{ !!([Int] ([Char[]] $Item -join '')) }
						Int		{ [Int] ([Char[]] $Item -join '') }
						Hex		{ [Char[]] $Item -join '' | ConvertFrom-Hex }
						Default { $Item }
					}
					$PSCmdlet.WriteDebug("End Field $_")
				}

				If(!$Folder.AESFolderKey -or !$Folder.RSAEncryptedFolderKey){
					'Share key not found for ID: {0}' -f $Folder.ID | Write-Warning
				}

				If($Folder.AESFolderKey){
					$Folder.Key = $Folder.AESFolderKey |
						ConvertFrom-LPEncryptedData |
						ConvertFrom-Hex
				}
				Else{
					$RSA = [RSACryptoServiceProvider]::New()
					$RSA.ImportParameters($Script:Session.PrivateKey)
					$Folder.Key = $RSA.Decrypt($Folder.RSAEncryptedFolderKey, $True) -join ''
				}
				$Folder.Name = $Folder.Name | ConvertFrom-LPEncryptedData -Base64 -Key $Folder.Key

				$Blob.SharedFolders.Add(([PSCustomObject] $Folder))
				$PSCmdlet.WriteDebug("END SHARE DECODE")
			}

			Default {
				If($Blob.ContainsKey($Type)){ $Blob[$Type] += $Data }
				Else{ $Blob[$Type] = @($Data) }
			}
		}
	}

	$Script:LastSyncTime = Get-Date
	$Script:Blob = [PSCustomObject] $Script:Blob
	If($PSBoundParameters.Debug){ Write-Output $Script:Blob }

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

	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSAvoidUsingConvertToSecureStringWithPlainText', '',
		Justification = 'Information has already been intentionally decrypted for output'
	)]
	[CmdletBinding()]
	Param(
		[Parameter(
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[String[]] $Name
	)

	BEGIN {
		If(!$Script:Session){ Throw 'User session not found. Log in with Connect-Lastpass' }
		$IDs = @()
	}

	PROCESS {
		If(!$Name){ Return $Script:Blob.Accounts | Select ID, Name }
		$Name | ForEach {
			$Script:Blob.Accounts | Where Name -eq $_ | Where ID -NotIn $IDs | ForEach {
				If($_.PasswordProtect){ Confirm-Password }

				$Account = @{}
				$Param = @{}
				If($_.ShareID){
					$Param.Key = $Blob.SharedFolders |
						Where ID -eq $_.ShareID |
						ForEach Key
				}

				$_.GetEnumerator() | ForEach {
					If($_.Key -eq 'FormFields'){
						$Account.FormFields = @()
						$_.Value | ForEach {
							$_ | Out-String | Write-Debug
							Write-Debug "FormField: $($_.Name)"
							$_.Value | Out-String | Write-Debug
							$Field = @{
								PSTypeName = 'Lastpass.FormField'
								Name = $_.Name
								Type = $_.Type
								Value = $_.Value
								Checked = $_.Checked
							}
							If($_.Value -is [SecureString]){
								$Param.SecureString = $_.Value
								$Field.Value = ConvertFrom-LPEncryptedData @Param
							}
							$Account.FormFields += [PSCustomObject] $Field
						}
					}
					ElseIf($_.Value -is [SecureString]){
						$Param.SecureString = $_.Value
						$Account[$_.Key] = ConvertFrom-LPEncryptedData @Param
					}
					Else{ $Account[$_.Key] = $_.Value }
				}

				$Credential = @{ Username = $Account.Username }
				If($Account.Password){
					[SecureString] $Credential.Password = $Account.Password |
						ConvertTo-SecureString -AsPlainText -Force
				}
				Else{ $Credential.Password = [SecureString]::Empty }

				$Account.Credential = [PSCredential]::New([PSCustomObject] $Credential)

				$Account.LastAccessed = [DateTime]::Now
				[PSCustomObject] $Account | Write-Output
				$IDs += $Account.ID
			}
		}
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

	.PARAMETER Account
	The Lastpass account to update

	.PARAMETER Name
	The name of the account

	.PARAMETER URL
	The URL of the account

	.PARAMETER Credential
	The account credentials

	.PARAMETER Notes
	The notes tied to the account

	.PARAMETER FormFields
	The account form fields

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

	[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
	Param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSTypeName('Lastpass.Account')] $Account,

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Name,

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $URL,

		[Parameter(ValueFromPipelineByPropertyName)]
		[PSCredential] $Credential,

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Notes,

		[Parameter(ValueFromPipelineByPropertyName)]
		[PSTypeName('Lastpass.FormField')] $FormFields,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $PasswordProtect,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $Favorite,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $AutoLogin,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $DisableAutofill
	)

	If(!$Script:Session){ Throw 'User session not found. Log in with Connect-Lastpass' }

	"Set-Account called with parameters:`n{0}" -f ($PSBoundParameters | Out-String) | Write-Debug
	If($FormFields){ Throw 'Updating accounts with form fields not supported currently' }

	$Param = @{
		ID				= $Account.ID
		Name			= $Name
		Folder			= $Account.Folder
		URL				= $URL
		Credential		= $Credential
		Notes			= $Notes
		FormFields		= $FormFields
		PasswordProtect	= $PasswordProtect
		Favorite		= $Favorite
		AutoLogin		= $AutoLogin
		DisableAutofill	= $DisableAutofill
	}
	If($Account.ShareID){ $Param.ShareID = $Account.ShareID }


	"Calling Set-Item with parameters:`n{0}" -f ($Param | Out-String) | Write-Debug
	Set-Item @Param
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
		[String[]] $Name
	)
	BEGIN {
		If(!$Script:Session){ Throw 'User session not found. Log in with Connect-Lastpass' }
		$IDs = @()
	}
	PROCESS {
		If(!$Name){ Return $Script:Blob.SecureNotes | Select ID, Name }
		$Name | ForEach {
			$Script:Blob.SecureNotes | Where Name -eq $_ | Where ID -NotIn $IDs | ForEach {
				If($_.PasswordProtect){ Confirm-Password }

				$Note = @{}
				$Param = @{}
				If($_.ShareID){
					$Param.Key = $Blob.SharedFolders |
						Where ID -eq $_.ShareID |
						ForEach Key
				}
				If($_.AttachmentKey){
					$AttachmentKey = $_.AttachmentKey |
						ConvertFrom-LPEncryptedData @Param -Base64 |
						ConvertFrom-Hex
				}
				$_.GetEnumerator() | Where Key -ne 'AttachmentKey' | ForEach {
					'Key: {0}' -f $_.Key | Write-Debug
					If($_.Key -eq 'Attachments'){
						$Note.Attachments = $_.Value | ForEach {
							[PSCustomObject] @{
								PStypeName = 'Lastpass.Attachment'
								ID = $_.ID
								MIMEType = $_.MIMEType
								StorageKey = $_.StorageKey
								Size = $_.Size
								FileName = $_.FileName |
									ConvertFrom-LPEncryptedData -Key $AttachmentKey -Base64
							}
						}
					}
					ElseIf($_.Value -is [SecureString]){
						$Note[$_.Key] = $_.Value | ConvertFrom-LPEncryptedData @Param
					}
					Else{ $Note[$_.Key] = $_.Value }
				}

				If(
					$Note.Notes -match ('^NoteType:(.*)') -and (
						$Matches[1] -in $Schema.SecureNote.Types.Values -or
						$Matches[1] -match '^Custom_(\d+)$'
					)
				){
					'Custom Note: {0}' -f $Matches[1] | Write-Debug
					$Notes = [Ordered] @{}
					$Note.Notes -split "`n" | ForEach {
						If(($Split = $_.IndexOf(':')) -ge 1){
							$Key = $_.Substring(0,$Split)
							$Notes[$Key] = $_.Substring(($Split+1))
						}
						Else{ $Notes[$Key] += "`n$_" }
					}
					$Note.Notes = $Notes
				}
				$Note.LastAccessed = [DateTime]::Now
				[PSCustomObject] $Note | Write-Output
				$IDs += $Note.ID
			}
		}
	}
}



Function Set-Note {
	<#
	.SYNOPSIS
	Updates a Lastpass Note

	.DESCRIPTION
	Sets the properties of a Lastpass note.
	Does a full overwrite (ie. any parameters not included will be
	deleted if they existed as part of the note previously)

	.PARAMETER Note
	The Lastpass secure note to update

	.PARAMETER Name
	The name of the note

	.PARAMETER Notes
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

	[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
	Param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSTypeName('Lastpass.SecureNote')] $Note,

		[Parameter(
			Mandatory,
			ValueFromPipelineByPropertyName
		)]
		[String] $Name,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Object] $Notes,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $PasswordProtect,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Switch] $Favorite
	)

	If(!$Script:Session){ Throw 'User session not found. Log in with Connect-Lastpass' }

	$Param = @{
		ID				= $Note.ID
		Name			= $Name
		Folder			= $Note.Folder
		Notes			= $Notes
		PasswordProtect	= $PasswordProtect
		Favorite		= $Favorite
	}

	If($Note.ShareID){ $Param.ShareID = $Note.ShareID }

	If($Notes -is [Collections.Specialized.OrderedDictionary]){
		$Param.Notes = ''
		$Notes.GetEnumerator() | ForEach {
			$Param.Notes += "{0}:{1}`n" -f $_.Key, $_.Value
		}
	}
	Set-Item @Param

}



Function Get-Attachment {
	<#
	.SYNOPSIS
	Gets a Secure Note attachment

	.DESCRIPTION
	Long description

	.PARAMETER Attachment
	The attachment metadata object

	.PARAMETER FilePath
	The path to save the attachment to.
	If the specified path is a directory, the attachment
	filename will be appended to the path automatically

	.PARAMETER Force
	If specified, the function will overwrite an existing file at the specified path
	By default if a file exists at the specified path, a confirmation prompt to overwrite is shown

	.EXAMPLE
	$Note = Get-Note 'AttachmentNote'
	Get-Attachment $Note.Attachments[0] $env:HOME/Downloads/secretfile.txt

	Downloads the first attachment of the 'AttachmentNote' secure note
	and saves it to the Downloads folder in the user's home directory with the name 'secretfile.txt'
	If a file already exists at that path, the function will prompt whether to overwrite

	.EXAMPLE
	New-Item -ItemType Directory Attachments -Force
	$Note = Get-Note 'AttachmentNote'
	$Note.Attachments | Get-Attachment -FilePath ./Attachments -Force

	Downloads all of the attachments of the 'AttachmentNote' secure note
	to the Attachments directory in the current directory.
	Each attachment is saved with it's respective original filename in Lastpass
	Any existing files are overwritten without confirmation
	#>

	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline)]
		[Alias('AttachmentMetadata')]
		[PSTypeName('Lastpass.Attachment')] $Attachment,

		[Parameter(Mandatory)]
		[ValidateScript({ Test-Path -IsValid $_ })]
		[String] $FilePath,

		[Switch] $Force
	)

	If(!$Script:Session){ Throw 'User session not found. Log in with Connect-Lastpass' }

	$NoteID = $Attachment.ID -split '-' | Select -First 1
	$Note = Get-Note | Where ID -eq $NoteID | Get-Note
	If(!$Note.AttachmentKey){ Throw 'Unable to find attachment key' }
	$Param = @{
		URI = 'https://lastpass.com/getattach.php'
		WebSession = $WebSession
		Method = 'Post'
		Body = @{
			token = $Session.Token
			getattach = $Attachment.StorageKey
		}
	}

	If($Note.ShareID){ $Param.Body.sharedfolderid = $Note.ShareID }

	Try{ $Content = Invoke-RestMethod @Param }
	Catch{ Throw "Failed to download attachment from Lastpass server`n{0}" -f $_ }

	# May need to unescape backslashes in response
	Try{
		$Content = $Content | ConvertFrom-LPEncryptedData -Base64 -Key $Note.AttachmentKey
		$Content = [Convert]::FromBase64String($Content)
	}
	Catch{ Throw "Failed to decrypt attachment`n{0}" -f $_ }


	If(Test-Path -PathType Container $FilePath){
		$FilePath = Join-Path $FilePath $Attachment.FileName
	}

	If(!$Force -and (Test-Path $FilePath)){
		Do{
			Switch(Read-Host ('Overwrite File {0}? (y/N)' -f $FilePath)){
				Y { $Break = $True }
				N { Return }
				'' { Return }
			}
		}While(!$Break)
	}

	Set-Content -Path $FilePath -Value $Content -AsByteStream
	Get-Item $FilePath | Write-Output
}



Function New-Password {
	<#
	.SYNOPSIS
	Generates a new cryptographically random password

	.DESCRIPTION
	Uses the Security.Cryptography.RNGCryptoServiceProvider class to generate random characters.
	By default it varies the length of the password to between 19 and 37 characters, to further
	randomize the output. Allows for specifying preset character sets of allowed characters,
	or specifying valid or invalid characters using regular expression set notation. The default
	output is a SecureString object; you can use the -AsPlainText parameter to output a string.

	.PARAMETER Length
	The length of the password
	By default, the length will be between 19 and 37 characters

	.PARAMETER InvalidCharacters
	The sets of invalid characters.
	Specify a regular expression character set.

	.PARAMETER ValidCharacters
	The sets of invalid characters.
	Specify a regular expression character set.

	.PARAMETER CharacterSet
	The preset character set of valid characters.

	.PARAMETER AsPlainText
	If set to true, the password will be output in plaintext instead of a securestring

	.EXAMPLE
	New-Password

	Generates a new random password

	.EXAMPLE
	New-Password -AsPlainString

	Generates a new random password output as a plaintext string
	By default, New-Password outputs a SecureString object

	.EXAMPLE
	New-Password -Length 25

	Generates a random 25 character password

	.EXAMPLE
	New-Password -InvalidCharacters "a-c\[\]\\\-"

	Generates a new random password without the characters a, b, c, [, ], \, or -
	This example shows the regex set notation, and the characters that need to be escaped with a
	preceding '\'

	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSUseShouldProcessForStateChangingFunctions', '',
		Justification = 'Does not change system state'
	)]
	[CmdletBinding(DefaultParameterSetName = 'InvalidCharacters')]
	Param(
		[Int] $Length,

		[Parameter(ParameterSetName = 'InvalidCharacters')]
		[String] $InvalidCharacters,

		[Parameter(ParameterSetName = 'ValidCharacters')]
		[String] $ValidCharacters,

		[ValidateSet(
			'Alphanumeric',
			'Alphabetic',
			'UpperCase',
			'LowerCase',
			'Numeric',
			'XML',
			'Base64'
		)]
		[Parameter(ParameterSetName = 'CharacterSet')]
		[String] $CharacterSet,

		[Switch] $AsPlainText
	)

	$ValidCharacterSet = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
							"0123456789``~!@#$%^&*()-_=+[{]}\|;:'`",<.>/? ")
	$CharacterSets = @{
		Alphanumeric = '^A-Za-z0-9'
		Alphabetic	 = '^A-Za-z'
		UpperCase	 = '^A-Z'
		LowerCase	 = '^a-z'
		Numeric		 = '^0-9'
		Base64		 = '^A-Za-z0-9+/='
		XML			 = "<>&`"'"
	}
	$RNG = [RNGCryptoServiceProvider]::New()
	$Bytes = [Byte[]]::New(4)

	Switch($PSCmdlet.ParameterSetName){
		InvalidCharacters { $Filter = "[$InvalidCharacters]" }
		ValidCharacters { $Filter = "[^$ValidCharacters]" }
		CharacterSet { $Filter = "[{0}]" -f $CharacterSets[$CharacterSet] }
	}
	If($Filter -notin $Null,'[]'){
		$ValidCharacterSet = $ValidCharacterSet -creplace $Filter
		"ValidCharacterSet: $ValidCharacterSet" | Write-Debug
		If(!$ValidCharacterSet.Length){ Throw 'No valid characters for generating password' }
	}

	If(!$Length){
		# Arbitrary numbers are arbitrary
		$MinLength = 19
		$MaxLength = 37
		$RNG.GetBytes($Bytes);
		$RandomNumber = [BitConverter]::ToUInt32($Bytes,0) % ($MaxLength - $MinLength + 1)
		$Length = $RandomNumber + $MinLength
	}

	$Password = 1..$Length | ForEach {
		$RNG.GetBytes($Bytes)
		$RandomNumber = [BitConverter]::ToUInt32($Bytes,0) % $ValidCharacterSet.Length
		$ValidCharacterSet[$RandomNumber]
	}

	If($AsPlainText){ $Password -join '' | Write-Output }
	Else{
		$SecurePassword = [SecureString]::New()
		0..($Password.Length-1) | ForEach {
			$SecurePassword.AppendChar($Password[$_])
			$Password[$_] = $Null
		}
		Write-Output $SecurePassword
	}

}



<#
New-Account {}


Remove-Account {}


New-Note {}


Remove-Note {}


New-Folder {}


Get-Folder {}


Set-Folder {}
	-Sharing


Remove-Folder {}


Reset-MasterPassword {}


Move-Folder?


#>

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

	.PARAMETER ShareID
	The ID of the share that contains the item

	.PARAMETER URL
	The URL of the item,
	If secure note, this is set to 'http://sn'

	.PARAMETER Credential
	The username of the account

	.PARAMETER Notes
	The item's notes

	.PARAMETER FormFields
	The item's formfields

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
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSAvoidOverwritingBuiltInCmdlets', '',
		Justification = 'Private function'
	)]
	[CmdletBinding(
		SupportsShouldProcess,
		ConfirmImpact = 'High',
		DefaultParameterSetName = 'Account'
	)]
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

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $ShareID,

		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[String] $URL,

		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[PSCredential] $Credential,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Alias('Content','Extra')]
		[String] $Notes,

		[Parameter(
			ParameterSetName='Account',
			ValueFromPipelineByPropertyName
		)]
		[PSTypeName('Lastpass.FormField')] $FormFields,

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

		# If shared
		# 	If share is Readonly, Throw
		#	append share id
		#	strip shared folder name from Folder/grouping property
		# Get account
		# Check if editable (IsShared and Share.ReadOnly)
		# Update modified property(ies)
		# 	generate new encrypted value (with new IV)
		# 	set unencrypted value
		# update_account
		# 	show_website.php
		# 		extjs = 1
		# 		token = $Token
		# 		method = 'cli'
		# 		name = $Account.Name (encrypted)
		# 		grouping = $Account.Folder.Name (encrypted)
		# 		pwprotect = 'on'/'off'
		# 		aid = $Account.ID
		# 		url = $Account.URL (hex)
		# 		username = $Account.Username (encrypted)
		# 		password = $Account.Password (encrypted)
		# 		extra = $Account.Notes (encrypted)
		# 		If $Account.SharedFolderID
		# 			sharedfolderid = $Account > Share.ID
		# save blob

		If($ShareID){
			If(($Blob.SharedFolders | Where ID -eq $ShareID).ReadOnly){
				$Type = If($SecureNote){ 'Note' }Else{ 'Account' }
				Throw ('{0} {1} is in a read-only shared folder' -f ($Type, $Name))
			}
			$Body = @{ sharedfolderid = $ShareID }
			$Folder = $Folder.Substring($Folder.IndexOf('\') + 1)
			$Key = $Blob.SharedFolders | Where ID -eq $ShareID | Select -Expand Key
		}

		If($SecureNote){
			$URL = 'http://sn'
			$VerboseDescription = "secure note '$Name'"
		}
		$Body += @{
			aid		 = $ID
			name	 = $Name | ConvertTo-LPEncryptedString -Key $Key
			grouping = $Folder | ConvertTo-LPEncryptedString -Key $Key
			url		 = ([Byte[]][Char[]] $URL | ForEach { "{0:x2}" -f $_ }) -join ''
			extra	 = $Notes | ConvertTo-LPEncryptedString -Key $Key
			<#
			folder = 'user'		#, 'none', or name of default folder
			#localupdate = 1	# ?
			#ajax = 1			# ?
			#source = 'vault'	# ?
			#urid = 0			# ?
			#auto = 1			# ?
			#iid = ''			# ?
			#save_all = 1		# Used for app fields?
			#data = ""			# Used for app fields?
			#>
		}
		If($PasswordProtect){ $Body.pwprotect = 'on' }
		If($Favorite){ $Body.fav = 'on' }

		If(!$SecureNote){
			$Body.username = $Credential.Username | ConvertTo-LPEncryptedString -Key $Key
			$Body.password = $Credential.GetNetworkCredential().Password |
				ConvertTo-LPEncryptedString -Key $Key

			# FIXME: This doesn't seem to work. Seems to match lastpass-cli code
			If($FormFields){
				$Body.data = ''
				$Body.data += $FormFields | ForEach {
					$Field = $_
					# $Field.Value.FieldType | Out-String | Write-Host
					$Value = Switch -Regex ($Field.Type){
						'email|tel|text|password|textarea' { $Field.Value | ConvertTo-LPEncryptedString -Key $Key }
						'checkbox|radio' { '{0}-{1}' -f $Field.Value, [Int] $Field.Checked }
						Default { $Field.Value }
					}

					"0`t{0}`t{1}`t{2}`n" -f @(
						[URI]::EscapeDataString($Field.Name)
						[URI]::EscapeDataString($Field.Type)
						[URI]::EscapeDataString($Value)
					)

				}
				$Body.data += "0`taction`t`taction`n0`tmethod`t`tmethod`n"
				# Write-Host $Body.Data
				$Body.data = ([Byte[]][Char[]] $Body.Data | ForEach { "{0:x2}" -f $_ }) -join ''
				# Write-Host $Body.Data
				$Body.save_all = '1'
			}
			If($AutoLogin){ $Body.autologin = 'on' }
			If($DisableAutofill){ $Body.never_autofill = 'on' }
			$VerboseDescription = "account '$Name'"
		}

		"Request Parameters:`n{0}" -f ($Body | Out-String) | Write-Debug
		$Query = "WARNING: update support is currently experimental`n" +
			"DATA LOSS MAY OCCUR (especially if item has form fields or attachments)`n" +
			"Update $VerboseDescription" -f $Name
		$VerboseDescription = "Updating $VerboseDescription"
		If($PSCmdlet.ShouldProcess($VerboseDescription,$Query,'Continue?')){
			Write-Verbose $VerboseDescription
			$Response = Invoke-RestMethod @Param -Body ($BodyBase + $Body)

			$Response.OuterXML | Out-String | Write-Debug
			Switch($Response.XMLResponse.Result.Msg){
				'AccountCreated' {

				}
				'AccountUpdated' {

				}
				Default {
					Throw ("Failed to update {0}.`n{1}" -f @(
						$Name
						$Response.OuterXML)
					)
				}
			}
		}
	}

	END { Sync-Lastpass -Debug:$False }
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
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSUseShouldProcessForStateChangingFunctions', '',
		Justification = 'Does not change system state'
	)]
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

	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSUseShouldProcessForStateChangingFunctions', '',
		Justification = 'Does not change system state'
	)]
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
	Reads an item from a Lastpass blob

	.PARAMETER Blob
	The Lastpass blob

	.PARAMETER Index
	The start index into the blob to start reading from

	.EXAMPLE
	Read-Item $Blob

	Reads an item from Lastpass Blob $Blob, starting from index 0

	.EXAMPLE
	Read-Item $Blob $Index

	Reads an item from Lastpass Blob $Blob, starting from index $Index

	#>

	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[Byte[]] $Blob,

		[Int] $Index = 0
	)
	Write-Debug "Read-Item start index: $Index"
	"Blob Snippet: {0}" -f ($Blob[$Index..($Index+50)] -join '') | Write-Debug


	$Size = $Blob[$Index..($Index+=3)]
	If([BitConverter]::IsLittleEndian){ [Array]::Reverse($Size) }
	$Size = [BitConverter]::ToUInt32($Size,0)
	Write-Debug "Size: $Size"
	If($Size){
		$Data = $Blob[($Index+=1)..(($Index+=$Size)-1)]
		Write-Debug "Data: $Data"
		Write-Output $Data
	}

}



Function Read-ASN1Item {
	<#
	.SYNOPSIS
	Parses an ASN1 encoded byte array

	.DESCRIPTION
	Lastpass' private key is sent using an ASN1 encoded byte array.
	This function does basic parsing of an ASN1 encoded data structure.

	.PARAMETER Blob
	The ASN1 encoded byte array

	.PARAMETER Index
	The start index into the byte array to start reading from

	.EXAMPLE
	Read-ASN1 -Blob $Blob

	Reads the ASN1 encoded item from the $Blob byte array, starting at index 0

	.EXAMPLE
	Read-ASN1 -Blob $Blob -Index $Index

	Reads the ASN1 encoded item from the $Blob byte array, starting at index $Index.
	#>

	[CmdletBinding()]
	Param(
		[Byte[]] $Blob,
		[Int] $Index = 0
	)

	Write-Debug "Read-ASN1Item Blob Length: $($Blob.Length), Index: $Index"
	$Output = @{
		Type = Switch($Blob[$Index] -band 0x1F){
			2		{ 'Integer' }
			4		{ 'Bytes' }
			5		{ 'Null' }
			16		{ 'Sequence' }
			Default { $Blob[$Index] -band 0x1F }
		}
	}
	$Size = $Blob[($Index+=1)]
	If(($Size -band 0x80) -ne 0){
		$Length = $Size -band 0x7F
		$Size = 0
		1..$Length | ForEach {
			$Size = $Size * 256 + ($Blob[($Index+=1)])
		}
	}
	$Output.Value = $Blob[($Index+=1)..(($Index+=$Size)-1)]
	$Output.Value -is [Array] | Write-Debug
	$Output.Index = $Index

	$Output | Out-String | Write-Debug
	Write-Output [PSCustomObject] $Output
}



Function ConvertFrom-LPEncryptedData {

	<#
	.SYNOPSIS
	Decrypts Lastpass encrypted strings

	.DESCRIPTION
	Decrypts data from Lastpass blob and transmission
	Supports CBC and ECB encryption
	If a SecureString is passed in, the bytes are extracted and then decrypted
	If a string is passed in, it is converted to a byte array and then decrypted

	.PARAMETER Data
	The encrypted Lastpass string to decrypt

	.PARAMETER SecureString
	The SecureString that holds an encrypted string as a byte array

	.PARAMETER Key
	If specified, this key will be used for decryption.
	By default, the account key will be used.

	.PARAMETER Base64
	Whether the input is Base64 encoded

	.EXAMPLE
	ConvertFrom-LPEncryptedData -Value '!lks;jf90s|fsafj9#IOj893fj'

	Decrypts the Lastpass encrypted input string

	.EXAMPLE
	$EncryptedAccounts.Name | ConvertFrom-LPEncryptedData

	Decrypts the names of the accounts in the $EncryptedAccounts variable

	.EXAMPLE
	$Key = [Convert]::FromBase64String('Bg0kRH2p+IC4mjRHlNm/IyNnfudsEXaaPLgHDeU0NTs=')
	'IVdYT0McSfObWOy68igNDsDDSoATbUwNSt/TFEMnu5hV' | ConvertFrom-LPEncryptedData -Key $Key -Base64

	Decrypts the Base64 encoded encrypted string using the specified key
	#>
	[CmdletBinding(DefaultParameterSetName='String')]
	[OutputType([String])]
	Param (
		[Parameter(
			ParameterSetName='String',
			ValueFromPipeline,
			ValueFromPipelineByPropertyName,
			Position = 0
		)]
		[Char[]] $Data,

		[Parameter(
			ParameterSetName='SecureString',
			ValueFromPipeline,
			ValueFromPipelineByPropertyName,
			Position = 0
		)]
		[SecureString] $SecureString,

		[Byte[]] $Key,

		[Switch] $Base64
	)

	BEGIN {
		If(!$Key -and !$Session.Key){ Throw 'No decryption key found.' }
		$AES = [AesManaged]::New()
		$AES.KeySize = 256
		$AES.Key = If($Key){
			Write-Debug ('Using custom key {0}...' -f ($Key[0..4] -join ','))
			$Key
		}
		Else{ $Session.Key }
	}

	PROCESS {
		# https://blogs.msdn.microsoft.com/fpintos/2009/06/12/how-to-properly-convert-securestring-to-string/
		If($PSCmdlet.ParameterSetName -eq 'SecureString'){
			$Data = [Char[]]::New($SecureString.Length)

			$Pointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
			Try{ [Runtime.InteropServices.Marshal]::Copy($Pointer, $Data, 0, $SecureString.Length) }
			Finally{ [Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Pointer) }
		}

		Write-Debug "Encrypted value $($Data.Length):"
		Write-Debug "$($Data -join '')"
		If($Data.length -eq 0){ Return '' }

		If($Base64){
			$Data = If($Data[0] -eq '!'){
				$Index = $Data.IndexOf([Char] '|')
				[Char[]] '!' +
				[Char[]][Convert]::FromBase64CharArray($Data, 1, $Index-1) +
				[Char[]][Convert]::FromBase64CharArray($Data, $Index+1, ($Data.Length-$Index-1))
			}
			Else { [Char[]][Convert]::FromBase64CharArray($Data, 0, $Data.Length)}
		}

		If(($Data[0] -eq '!') -and ($Data.Length -gt 32) -and ($Data.Length % 16 -eq 1)){
			Write-Debug 'CBC'
			$AES.Mode = [CipherMode]::CBC
			$AES.IV = $Data[1..16]
			$Data = $Data[17..($Data.Length-1)]
		}
		Else{
			Write-Debug 'ECB'
			$AES.Mode = [CipherMode]::ECB
			$AES.IV = [Byte[]] '0'*16
		}
		$AES | Out-String | Write-Debug
		$Decryptor = $AES.CreateDecryptor()

		Try{
			[Char[]] $Decryptor.TransformFinalBlock(
				$Data,
				0,
				$Data.length
			) -join ''
		}
		Catch{
			Write-Error "Decryption failed. Data: $Data"
			Throw
		}
	}
}



Function ConvertTo-LPEncryptedString {

	<#
	.SYNOPSIS
	Encrypts Lastpass encoded strings

	.DESCRIPTION
	Encrypts strings for communication with Lastpass and storage

	If a string is passed in, it will convert it into a CBC encrypted value in the format Lastpass
	expects for upload or communication.

	If a byte array is passed in, it will convert them into a SecureString object. This is useful
	for decryption of the Lastpass account blob without generating a plaintext string

	.PARAMETER Value
	The string to encrypt

	.PARAMETER Bytes
	The array of characters to convert into a SecureString

	.PARAMETER Key
	If specified, this key will be used for encryption.
	By default, the account key will be used.

	.EXAMPLE
	ConvertTo-LPEncryptedString -Value 'SecretText'

	Encrypts the input string 'SecretText'

	.EXAMPLE
	$DecryptedAccounts.Username | ConvertTo-LPEncryptedString

	Encrypts the names of the accounts in the $DecryptedAccounts variable

	.EXAMPLE
	ConvertTo-LPEncryptedString -Bytes $Bytes

	Converts the byte array $Bytes into a SecureString object, suitable for in memory storage
	#>

	[CmdletBinding(DefaultParameterSetName='String')]
	[OutputType([String], ParameterSetName='String')]
	[OutputType([SecureString], ParameterSetName='SecureString')]
	Param (
		[Parameter(
			ParameterSetName='String',
			ValueFromPipeline,
			ValueFromPipelineByPropertyName,
			Position = 0
		)]
		[AllowEmptyString()]
		[String[]] $Value,

		[Parameter(
			ParameterSetName='SecureString',
			Position = 0
		)]
		[AllowEmptyCollection()]
		[Byte[]] $Bytes,

		[Byte[]] $Key
	)

	BEGIN {
		If($PSCmdlet.ParameterSetName -eq 'String'){
			If(!$Key -and !$Session.Key){ Throw 'No decryption key found.' }
			$AES = [AesManaged]::New()
			$AES.KeySize = 256
			$AES.Key = If($Key){
				Write-Debug ('Using custom key {0}...' -f ($Key[0..4] -join ','))
				$Key
			}
			Else{ $Session.Key }
			$AES.Mode = [CipherMode]::CBC
		}
	}

	PROCESS {
		If($PSCmdlet.ParameterSetName -eq 'SecureString'){
			$Output = [SecureString]::New()
			If($Bytes){
				0..($Bytes.Length-1) | ForEach {
					$Output.AppendChar($Bytes[$_])
					$Bytes[$_] = $Null
				}
			}
			Return $Output
		}
		$Value | ForEach {
			If(!$Value){ Return ''}
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
	Decodes a hex string

	.PARAMETER Value
	The hex encoded string

	.EXAMPLE
	ConvertFrom-Hex '56616C7565'

	Decodes the hex string to 86,97,108,117,101 ('Value')

	.EXAMPLE
	'506970656C696E6556616C7565' | ConvertFrom-Hex

	Decodes the hex string to 80,105,112,101,108,105,110,101,86,97,108,117,101 ('PipelineValue')
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
			If($_){ [Convert]::ToByte($_,16) }
		})
	}

}



Function Confirm-Password {
	<#
	.SYNOPSIS
	Reprompts and reverifies the master account password

	.DESCRIPTION
	Prompts the user for the master password and verifies it is correct
	If the password has been verified within the verification timeout setting, verification is skipped
	If the password entered is incorrect, the function will throw an error

	.EXAMPLE
	Confirm-Password

	Checks whether the master password has been verified within the timeout setting,
	and if not, prompts the user to re-enter their password and verifies it is correct.
	#>

	[CmdletBinding()]
	Param()

	If($PasswordPrompt -lt [DateTime]::Now.Subtract($PasswordTimeout)){
		#TODO: Should this loop? Possibly for a set number of retries?
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


}



Function Get-Session {
	<#
	.SYNOPSIS
	Returns a Lastpass session.
	For Debugging purposes only.

	.EXAMPLE
	Get-Session

	Gets the Lastpass session object

	#>

	Return [PSCustomObject] @{
		PSTypeName = 'Lastpass.Session'
		WebSession = $WebSession
		Session = $Session
		Blob = $Blob
	}
}



Function Set-Session {
	<#
	.SYNOPSIS
	Sets the Lastpass session
	For debugging purposes only

	.PARAMETER Session
	The lastpass session oobject

	.EXAMPLE
	Set-Session $S

	Sets the Lastpass session

	.EXAMPLE
	$S | Set-Session

	Sets the Lastpass session
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
		'PSUseShouldProcessForStateChangingFunctions', '',
		Justification = 'Does not change system state'
	)]
	Param(
		[Parameter(
			Mandatory,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName,
			Position = 0
		)]
		[PSTypeName('Lastpass.Session')] $Session
	)

	$Script:WebSession = $Session.WebSession
	$Script:Session = $Session.Session

}



$ExportMethods = @(
	'Connect-Lastpass'
	'Disconnect-Lastpass'
	'Sync-Lastpass'
	'Get-Account'
	'Get-Note'
	'Get-Attachment'
	'New-Password'
)

If($ModuleParameters.ExportWriteCmdlets){
	"Modification cmdlets are currently experimental " +
	"and should not be used for production workloads.`n" +
	"DATA LOSS MAY OCCUR!" | Write-Warning
	$ExportMethods += @(
		'Set-Account'
		'Set-Note'
	)
}

If($ModuleParameters.Debug){
	$ExportMethods = '*'
}
Export-ModuleMember -Function $ExportMethods