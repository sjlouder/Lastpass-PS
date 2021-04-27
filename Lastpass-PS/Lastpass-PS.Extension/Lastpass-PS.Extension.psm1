Function Get-Secret {
	[CmdletBinding()]
	Param (
		[String] $Name,
		[String] $VaultName,
		[Hashtable] $AdditionalParameters
	)
	# Test this!
	(Get-Account -Name $Name)?[0] ?? (Get-Note -Name $Name)?[0]

	#Return [TestStore]::GetItem($Name, $AdditionalParameters)
}

Function Get-SecretInfo {
	[CmdletBinding()]
	Param (
		[string] $Name,
		[string] $VaultName,
		[hashtable] $AdditionalParameters
	)

	# By default, return accouts and notes
	# How to handle Attachments?
	#	Don't consider them secrets. Use the lastpass API
	# Name seems to be the only filter
	# Type as Additional Parameter?

	# Because this is metadata onlty
	#	grab from vault object directly to bypass unnecessarily secret decryption
	#	or add -OnlyMetadata parameter to Get-Account/Get-Note
	$Param = @{ MetadataOnly = $True }
	If($Name){ $Param.Name = $Name }

	Get-Account @Param | ForEach {
		# Return SecretInformation objects
		# Return [Microsoft.PowerShell.SecretManagement.SecretInformation]::New(
		# 	$Secret.Name,
		# 	[Microsoft.PowerShell.SecretManagement.SecretType]::SecureString,
		# 	$VaultName,
		# 	$Metadata
		# )
	}
	Get-Note @Param | ForEach {
		# Return SecretInformation objects
		# Return [Microsoft.PowerShell.SecretManagement.SecretInformation]::New(
		# 	$Secret.Name,
		# 	[Microsoft.PowerShell.SecretManagement.SecretType]::SecureString,
		# 	$VaultName,
		# 	$Metadata
		# )

	}

}

Function Set-Secret {
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $Name,

        [Parameter(ValueFromPipelineByPropertyName)]
		[Object] $Secret,

		[Parameter(ValueFromPipelineByPropertyName)]
		[String] $VaultName,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Hashtable] $AdditionalParameters
	)

	Write-Warning 'Saving secrets not currently supported'
	Return $False
	# Return boolean success value
}

# Optional function
Function Set-SecretInfo {
	[CmdletBinding()]
	param (
		[string] $Name,
		[hashtable] $Metadata,
		[string] $VaultName,
		[hashtable] $AdditionalParameters
	)

	Write-Warning "Saving secret metadata not currently supported"
	Return $False
}

Function Remove-Secret {
	[CmdletBinding()]
	param (
		[string] $Name,
		[string] $VaultName,
		[hashtable] $AdditionalParameters
	)

	Write-Warning "Removing secrets not currently supported"
	Return $False
}

Function Test-SecretVault {
	[CmdletBinding()]
	param (
		[string] $VaultName,
		[hashtable] $AdditionalParameters
	)
	# Test Blob/Vault or Session object exists?
	# Offline support?
	# Return boolan success value
}

# Optional function
# Function Unregister-SecretVault {
# 	[CmdletBinding()]
# 	param (
# 		[string] $VaultName,
# 		[hashtable] $AdditionalParameters
# 	)

# }