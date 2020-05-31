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
	[Switch] $Visible
)


#TODO: Download blob
# It does not seem to get stored in javascript, so need to call manually
# Maybe: scrape session details for API call? Call may work in session as is
# 

# https://www.selenium.dev/documentation/en/
# https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Headless_mode
#$Driver.FindElement(By.Name("q")).SendKeys("cheese" + Keys.Enter)
#$wait = new WebDriverWait(driver, TimeSpan.FromSeconds(10))
#$firstResult = $wait.Until(ExpectedConditions.ElementExists(By.CssSelector("h3>div")))

Add-Type -Path $PSScriptRoot/WebDriver.dll

$Options = [OpenQA.Selenium.Firefox.FirefoxOptions]::New()
If(!$Visible){ $Options.AddArguments('-headless') }

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

	Write-Verbose 'Getting Data'
	$Version = $Driver.ExecuteScript('return g_server_accts_version')

	$Accounts = $Driver.ExecuteScript('return JSON.stringify(g_sites)') |
		ConvertFrom-JSON -AsHashTable

	$SecureNotes = $Driver.ExecuteScript('return JSON.stringify(g_securenotes)') |
		ConvertFrom-JSON -AsHashTable

	$Attachments = $Driver.ExecuteScript('return JSON.stringify(lp_attaches)') |
		ConvertFrom-JSON -AsHashTable

	$Shares = $Driver.ExecuteScript('return JSON.stringify(g_shares)') |
		ConvertFrom-JSON -AsHashTable

	$Driver.ExecuteScript("return $.ajax({
		type: 'GET',
		url: base_url + 'getaccts.php',
		data: 'mobile=1&b64=1&requestsrc=cli&hasplugin=3.0.23',
		success: function (a) {return a}})") | Out-File $PSScriptRoot/Vault
		# dataType: 'text',
	# $Blob | Out-File $PSScriptRoot/Vault
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
	If($_.url -eq 'http://group'){ # is a folder
		If($_.created_gmt){ # is not a share
			$Folder = [Ordered] @{
				ID = $_.aid
				Name = $_.group
				FIID = $_.fiid
				DateCreated = $_.created_gmt
				LastAccessed = $_.last_touch
				LastModifiedGMT = $_.last_modified_gmt
				LastPasswordChange = $_.last_pwchange_gmt
			}
			If($_.sharefolderid){ $Folder.ShareID = $_.sharefolderid }
			$Parsed.Folders += $Folder
		}
	}
	Else {
		$Account = [Ordered] @{
			ID = $_.aid
			Name = $_.name
			Folder = $_.group ? $_.group : $Null
			URL = $_.url ? $_.url : $Null
			Notes = $_.extra ? $_.extra : $Null
			Favorite = !![Int] $_.fav
			Username = $_.username
			Password = $_.password ? $_.password : $Null
			PasswordProtect = !![Int] $_.pwprotect
			generatedpassword = !![Int] $_.genpw
			securenote = !![Int] $_.sn
			LastAccessed = $_.last_touch
			AutoLogin = !![Int] $_.autologin
			NeverAutofill = !![Int] $_.never_autofill
			realmdata = $_.realm_data ? $_.realm_data : $Null
			FIID = $_.fiid
			customjs = $_.custom_js ? $_.custom_js : $Null
			submitid = $_.submit_id ? $_.submit_id : $Null
			captchaid = $_.captcha_id ? $_.captcha_id : $Null
			URID = $_.urid
			Method = $_.method ? $_.method : $Null
			Action = $_.action ? $_.action : $Null
			BasicAuth = !![Int] $_.basic_auth
			GroupID = $_.groupid ? $_.groupid : $Null
			deleted = !![Int] $_.deleted
			AttachmentKey = $_.attachkey ? $_.attachkey : $Null
			attachmentpresent = !![Int] $_.attachpresent
			IndividualShare = !![Int] $_.individualshare
			NoteType = $_.notetype ? $_.notetype : $Null
			NoAlert = $_.noalert ? $_.noalert : $Null
			lastmodifiedgmt = $_.last_modified_gmt
			HasBeenShared = !![Int] $_.hasbeenshared
			lastpasswordchange = $_.last_pwchange_gmt
			DateCreated = $_.created_gmt
			Vulnerable = $_.vulnerable ? $_.vulnerable : $Null
		}
		If($_.sharefolderid){ $Account.ShareID = $_.sharefolderid }
		If($_.fields){
			$Account.FormFields = @()
			$_.fields | ForEach {
				$Account.FormFields += [Ordered] @{
					Name = $_.name
					Checked = !![Int] $_.checked
					FormName = $_.formname ? $_.formname : $Null
					OtherField = !![Int] $_.otherfield
					OtherLogin = $_.otherlogin
					Type = $_.type
					URID = $_.urid
					URL = $_.url ? $_.url : $Null
					Value = $_.value ? $_.value : $Null
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
		Folder = $_.group ? $_.group : $Null
		NoteType = $_.notetype ? $_.notetype : $Null
		Notes = $_.extra ? $_.extra : $Null
		AttachmentPresent = !![Int] $_.attachpresent
		AttachmentKey = $_.attachkey ? $_.attachkey : $Null
		PasswordProtect = !![Int] $_.pwprotect
		Favorite = !![Int] $_.fav
		Deleted = !![Int] $_.deleted
		HasBeenShared = !![Int] $_.hasbeenshared
		FIID = $_.fiid
		DateCreated = $_.created_gmt
		LastAccessed = $_.last_touch
		LastModifiedGMT = $_.last_modified_gmt
		LastPasswordChange = $_.last_pwchange_gmt
	}
	If($_.sharefolderid){ $Note.ShareID = $_.sharefolderid }
	$Attachments | Where Parent -eq $Note.ID | ForEach {
		If(!$Note.Attachments){ $Note.Attachments = @() }
		$Note.Attachments += [Ordered] @{
			ID = $_.id
			Parent = $_.parent
			MIMEType = $_.mimetype
			StorageKey = $_.storagekey
			Size = $_.size
			FileName = $_.filename
		}
	}
	$Parsed.SecureNotes += $Note

}


$Shares | ForEach {
	$Parsed.SharedFolders += [Ordered] @{
		ID = $_.id
		RSAEncryptedFolderKey = $_.sharekey
		Name = $_.decsharename
		ReadOnly = !![Int] $_.readonly
		Give = !![Int] $_.give
		AESFolderKey = $_.sharekeyaes
		Key = $_.key
	}
}


$Parsed | ConvertTo-Json -Depth 10 | Out-File $PSScriptRoot/ParsedVault.json