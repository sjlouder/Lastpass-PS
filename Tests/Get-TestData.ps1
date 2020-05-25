<#
.SYNOPSIS
Generates new testing data files

.DESCRIPTION
Generates a new parsed vault json testing file
by using Selenium to log in to Lastpass and grabbing
the values parsed by the reference javascript library

.PARAMETER Credential
The credential of the account to login to Lastpass with

.PARAMETER Path
The path of the output json file
#>

[CmdletBinding()]
Param(
	[PSCredential] $Credential,
	[String] $Path
)

# https://www.selenium.dev/documentation/en/
# https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Headless_mode
#$Driver.FindElement(By.Name("q")).SendKeys("cheese" + Keys.Enter)
#$wait = new WebDriverWait(driver, TimeSpan.FromSeconds(10))
#$firstResult = $wait.Until(ExpectedConditions.ElementExists(By.CssSelector("h3>div")))

Add-Type -Path $PSScriptRoot/WebDriver.dll

$Options = [OpenQA.Selenium.Firefox.FirefoxOptions]::New()
#$Options.AddArguments('-headless')

Write-Verbose 'Starting browser'
$Driver = [OpenQA.Selenium.Firefox.FirefoxDriver]::New($Options)
Try{
	Write-Verbose 'Navigating to Lastpass'
	$Driver.Navigate().GoToUrl('https://www.Lastpass.com/')
	$Driver.FindElementsByLinktext('Log In').Click()

	Write-Verbose 'Logging in'
	$Driver.FindElementById('email').SendKeys($Credential.Username)
	$Driver.FindElementById('password').SendKeys($Credential.GetNetworkCredential().Password)
	$Driver.FindElementById('buttonsigningo').Click()
	Start-Sleep 10 # Webdriver wait
	#TODO: MFA id Fyubikey

	$Version = $Driver.ExecuteScript('return g_server_accts_version')

	$Accounts = $Driver.ExecuteScript('return JSON.stringify(g_sites)') |
		ConvertFrom-JSON -AsHashTable

	$SecureNotes = $Driver.ExecuteScript('return JSON.stringify(g_securenotes)') |
		ConvertFrom-JSON -AsHashTable

	$Attachments = $Driver.ExecuteScript('return JSON.stringify(lp_attaches)') |
		ConvertFrom-JSON -AsHashTable

	$Shares = $Driver.ExecuteScript('return JSON.stringify(g_shares)') |
		ConvertFrom-JSON -AsHashTable


	# Get decrypted values from DOM
	# Maybe: get blob, use vault.js to parse/decrypt items

}
Finally{
	Write-Verbose 'Closing browser'
	$Driver.Close()
}


Write-Verbose 'Normalizing values'
$Parsed = @{
	Version = $Version
	Accounts = @()
	Folders = @()
	SecureNotes = @()
	SharedFolders = @()
}

$Accounts.Values | ForEach {
	If($_.url -eq 'http://group'){
		$Folder = [Ordered] @{
			ID = $_.aid
			Name = $_.name
			FIID = $_.fiid
			DateCreated = $_.created_gmt
			LastAccessed = $_.last_touch
			LastModifiedGMT = $_.last_modified_gmt
			LastPasswordChange = $_.last_pwchange_gmt
		}
		If($_.sharedfromaid){ $Folder.ShareID = $_.sharedfromaid }
		$Attachments | Where Parent -eq $Folder.ID | ForEach {
			If(!$Folder.Attachments){ $Folder.Attachments = @() }
			$Folder.Attachments += [Ordered] @{
				ID = $_.id
				Parent = $_.parent
				MIMEType = $_.mimetype
				StorageKey = $_.storagekey
				Size = $_.size
				FileName = $_.filename
			}
		}
		$Parsed.Folders += $Folder
	}
	Else {
		$Account = [Ordered] @{
			ID = $_.aid
			Name = $_.name
			Folder = $_.group
			URL = $_.url
			Notes = $_.extra
			Favorite = $_.fav
			Username = $_.username
			Password = $_.password
			PasswordProtect = $_.pwprotect
			generatedpassword = $_.genpw
			securenote = $_.sn
			LastAccessed = $_.last_touch
			AutoLogin = $_.autologin
			NeverAutofill = $_.never_autofill
			realmdata = $_.realm_data
			FIID = $_.fiid
			customjs = $_.custom_js
			submitid = $_.submit_id
			captchaid = $_.captcha_id
			URID = $_.urid
			Method = $_.method
			Action = $_.action
			BasicAuth = $_.basic_auth
			GroupID = $_.groupid
			deleted = $_.deleted
			AttachmentKey = $_.attachkey
			attachmentpresent = $_.attachpresent
			IndividualShare = $_.individualshare
			NoteType = $_.notetype
			NoAlert = $_.noalert
			lastmodifiedgmt = $_.last_modified_gmt
			HasBeenShared = $_.hasbeenshared
			lastpasswordchange = $_.last_pwchange_gmt
			DateCreated = $_.created_gmt
			Vulnerable = $_.vulnerable
		}
		If($_.sharefolderid){ $Account.ShareID = $_.sharefolderid }
		If($_.fields){
			$Account.FormFields = @()
			$_.fields | ForEach {
				$Account.FormFields += [Ordered] @{
					Name = $_.name
					Checked = $_.checked
					FormName = $_.formname
					OtherField = $_.otherfield
					OtherLogin = $_.otherlogin
					Type = $_.type
					URID = $_.urid
					URL = $_.url
					Value = $_.value
				}
			}
		}
		$Parsed.Accounts += $Account
	}
}

$SecureNotes.Values | ForEach {
	$Note = [Ordered] @{
		ID = $_.aid
		Name = $_.name
		Folder = $_.group
		NoteType = $_.notetype
		Notes = $_.extra
		AttachmentPresent = $_.attachpresent
		AttachmentKey = $_.attachkey
		PasswordProtect = $_.pwprotect
		Favorite = $_.fav
		Deleted = $_.deleted
		HasBeenShared = $_.hasbeenshared
		FIID = $_.fiid
		DateCreated = $_.created_gmt
		LastAccessed = $_.last_touch
		LastModifiedGMT = $_.last_modified_gmt
		LastPasswordChange = $_.last_pwchange_gmt
	}
	If($_.sharefolderid){ $Note.ShareID = $_.sharefolderid }

	$Parsed.SecureNotes += $Note

}


$Shares | ForEach {
	$Parsed.SharedFolders += [Ordered] @{
		ID = $_.id
		RSAEncryptedFolderKey = $_.sharekey
		Name = $_.name
		ReadOnly = $_.readonly
		Give = $_.give
		AESFolderKey = $_.sharekeyaes
	}
}


$Parsed | ConvertTo-Json -Depth 10 | Out-File $Path