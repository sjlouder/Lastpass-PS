# Lastpass-PS
Lastpass Powershell Module

[![Build Status](https://dev.azure.com/sacrificialarts/sacrificialarts/_apis/build/status/sjlouder.Lastpass-PS?branchName=master)](https://dev.azure.com/sacrificialarts/sacrificialarts/_build/latest?definitionId=1&branchName=master)

# DESCRIPTION
Powershell module to interact with Lastpass.
 
Built on pure Powershell/.NET core, designed to work without any other external dependencies (eg. cygwin, openSSL) to maximize cross platform portability.

Based on [lastpass-cli](https://github.com/lastpass/lastpass-cli) and [lastpass-sharp](https://github.com/detunized/lastpass-sharp).

# QUICKSTART
```
# Prompts for credentials
Connect-Lastpass

# You can also include the app MFA code
$Credential = Get-Credential
Connect-Lastpass -Credential $Credential -OneTimePassword '038502'

# Get specific account by name
$GmailAccount = Get-Account 'Gmail'

# Get PSCredential that can be used in other Powershell commands
$GmailAccount.Credential

# Or, get username and password directly
$GmailAccount.Username
$GmailAccount.Password

# Update account information
# NOTE: This is experimental! See status section below for details
$GmailAccount | Set-Account -PasswordProtect

# Generate a new secure password
$Password = New-Password -Length 23 -ValidCharacters 'A-Za-z0-9%*&'

```
For more examples, check Tests/Lastpass.Tests.ps1.
For specific documentation of a function, use ```Get-Help <functionName>```


# STATUS AND FEATURES
This project is in early stages and is not production ready. Logging in, getting the account data, and decrypting fields has been implemented.

Currently supported:
* Login
	* App OTP MFA
	* Duo MFA
* Get and decrypt accounts and notes
	* Supports shared accounts and notes
	* Parses custom notes
	* Supports password protection
		* Currently, there is no UI to set a timespan between reprompts
	* Supports form fields
	* Supports downloading attachments
* Password generation

Experimental/in development:
* Update accounts and notes
	* **WARNING**: Not fully tested. **Create backup copies of your data before using this project to make any modifications.**
	* **WARNING**: Shared items not currently supported
	* **WARNING**: Custom Notes not fully tested
	* **WARNING**: Attachments and form fields are not currently supported and will be **lost**!
	* **NOTE**: These functions (Set-Account and Set-Note) are not exposed by default while they are in
	development. In order to enable these functions, pass in a hashtable to the module with a key
	named "ExportWriteCmdlets" and the value set to $True, eg:
	```
	Import-Module Lastpass -ArgumentList @{ ExportWriteCmdlets = $True }
	```

Planned:
* Full Accounts Support
	* Create/delete
	* Move (folders)
	* Sharing
* Full Notes support
	* Create/delete
	* Move
	* Sharing
* Other Login methods
	* Yubikey
	* Sesame
* Folder management support
	* Create/update/delete
	* Move
	* Un/share
	* Manage sharing
* Full Attachment support
	* Create/update/delete
* Import/export
* Lastpass:\ PS Drive (Hierarchical browsing of folders/accounts/notes) 
* Logout
* Change master password

Ideas:
* Create custom note types
* Automatic/Background Syncing
* Admin:
	* User management
	* Usergroup management
	* Sharing restrictions
	* MFA settings


# INSTALLING
Currently: download; Import-Module /Path/To/Lastpass-PS/Lastpass

Eventually: Install-Module Lastpass #From Powershell Gallery

# CONTRIBUTING
While this is still early in development (pre-1.0), I'm mostly looking for testers and test writers, feature ideas/priority, and help with documentation. Pull requests are welcome, but this is a side project so collaboration will likely be slow.

# LICENSE
GPLv2+. See LICENSE file for details
