# Lastpass-PS
Lastpass Powershell Module

.DESCRIPTION
---
Powershell module to interact with Lastpass.

Built on pure Powershell/.NET core, designed to work without any other external dependencies to maximize cross platform portability.

Based on [lastpass-cli](https://github.com/lastpass/lastpass-cli) and [lastpass-sharp](https://github.com/detunized/lastpass-sharp).

.EXAMPLE
---
```
$Credential = [PSCredential]::New(
	'eamil@provider.com',
	(ConvertTo-SecureString -A -F 'password')
)
$Connection = Connect-Lastpass -Credential $Credential

# Doesn't work yet
$AllAccounts = Get-Account

$GmailAccount = Get-Account 'Gmail'

$GmailAccount
```

STATUS AND FEATURES
---
This project is in early stages and currently only supports logging in, getting the account data, and decrypting fields. Current focus is on developing the specs (BDD Pester tests).

Currently supported:
* Login
	* App OTP MFA

Planned:
* Accounts Support
	* Create/read/update/delete
	* Move (folders)
* Notes support
	* Create/read/update/delete
	* Move
	* Parse special types
* Other Login methods
	* Yubikey
	* Sesame
	* Duo
* Folders support
	* Create/read/update/delete
	* Move
	* Un/share
	* Manage sharing
* Password reprompt
* Password generation
	* Specific length, specify dis/allowed characters
* Import/export
* Lastpass:\ PS Drive (Hierarchical browsing of folders/accounts/notes) 
* Logout
* Change master password
* Automatic syncing

Ideas:
* Create custom note types
* Background Syncing


INSTALLING
---
Eventually: Install-Module Lastpass #From Powershell Gallery
Currently: download; Import-Module /Path/To/Lastpass


CONTRIBUTING
---
See Contribute wiki page.
Tests (Pester/TDD), Design (Powershell/.NET core base)

LICENSE
---
GPLv2+. See LICENSE file for details
