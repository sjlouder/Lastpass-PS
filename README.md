# Lastpass-PS
Lastpass Powershell Module

[![Build Status](https://dev.azure.com/sacrificialarts/sacrificialarts/_apis/build/status/sjlouder.Lastpass-PS?branchName=master)](https://dev.azure.com/sacrificialarts/sacrificialarts/_build/latest?definitionId=1&branchName=master)

DESCRIPTION
=======
Powershell module to interact with Lastpass.
 
Built on pure Powershell/.NET core, designed to work without any other external dependencies to maximize cross platform portability.

Based on [lastpass-cli](https://github.com/lastpass/lastpass-cli) and [lastpass-sharp](https://github.com/detunized/lastpass-sharp).

EXAMPLE
---
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
$GmailAccount | Set-Account -PasswordProtect

```
For more examples, check Tests/Lastpass.Tests.ps1.


STATUS AND FEATURES
---
This project is in early stages and is not production ready. Logging in, getting the account data, and decrypting non shared fields has been implemented. Basic account and note updating has been implemented, but is not heavily tested.
**Create backup copies of your data before using this project to make any modifications.**

Currently supported:
* Login
	* App OTP MFA
* Get and decrypt accounts and notes
	* Supports password protection
* Update accounts and notes
	* **WARNING**: Not fully tested
	* **WARNING**: Shared items not currently supported

Planned:
* Accounts Support
	* Create/delete
	* Move (folders)
	* Sharing
* Notes support
	* Create/delete
	* Move
	* Sharing
	* Parse special types
* Other Login methods
	* Duo
	* Yubikey
	* Sesame
* Folders support
	* Create/read/update/delete
	* Move
	* Un/share
	* Manage sharing
* Attachment support
	* Create/read/update/delete
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
* Admin:
	* User management
	* Usergroup management
	* Sharing restrictions
	* MFA settings


INSTALLING
---
Currently: download; Import-Module /Path/To/Lastpass-PS/Lastpass

Eventually: Install-Module Lastpass #From Powershell Gallery

CONTRIBUTING
---
TODO
See Contribute wiki page.
Tests (Pester/TDD), Design (Powershell/.NET core base)

LICENSE
---
GPLv2+. See LICENSE file for details
