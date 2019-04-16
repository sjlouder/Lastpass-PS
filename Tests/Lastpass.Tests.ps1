Import-Module -Force $PSScriptRoot/../Lastpass -Verbose:$False

InModuleScope Lastpass {

	$ScriptRoot = $PSScriptRoot

	Describe Connect-Lastpass {

		# Catch all mock to make sure tests don't reach out to the internet
		Mock Invoke-RestMethod {}

		$IterationsMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/iterations.php' }
			MockWith = { 100100 }
		}
		Mock @IterationsMockParam
 
		$LoginMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/login.php' }
			MockWith = { 
				Return [PSCustomObject] @{
					Response = [PSCustomObject] @{
						OK = [PSCustomObject] @{
							UID				= '123456789'
							SessionID		= 'SessionIDHere1232'
							Token			= 'TokenHere12332o432i432'
							PrivateKeyEnc	= 'TestPrivateKey0-324irfk49-'
							Iterations		= '100100'
							Username		= 'Username'
						}
					}
				}
			}
	
		}
		Mock @LoginMockParam

		Mock Sync-Lastpass {
			[XML] (Get-Content "$ScriptRoot/Vault.xml").Response
		}

		$Credential = [PSCredential]::New(
			'Username',
			(ConvertTo-SecureString -A -F 'Password')
		)
		Connect-Lastpass $Credential | Out-Null

		It 'Gets the number of iterations' {
			Assert-MockCalled 'Invoke-RestMethod' -ParameterFilter {
				$URI -eq 'https://lastpass.com/iterations.php'
			}
		}

		It 'Creates an authenticated session with the server' {
			Assert-MockCalled 'Invoke-RestMethod' -ParameterFilter {
				$URI -eq 'https://lastpass.com/login.php'
			}
		}
		
		# TODO: Refactor  this to separate tests for New-Key and New-LoginHash
		Context 'Hash tests' {
			@(
				@{
					Username = 'Username'
					Password = 'Password'
					Iterations = 1
					Hash = '865a88b83cd3a0ecd3432c6deb55f5a525a937771ff75f1b20d7ee5a753e1dc8'
				},
				@{
					Username = 'postlass@gmail.com'
					Password = "ThisIsn'tTheRealPassword"
					Iterations = 500
					Hash = 'ccf6e7700c0befea3d4e28f6f368c8b08b0151d538c0d4b982117fb70acc1621'
				},
				@{
					Username = 'NobodyHere1324+lastpasstest@gmail.com'
					Password = 'NobodyHere1324+lastpasstest@gmail.com'
					Iterations = 100100
					Hash = 'fd2e5a470d72f8b80ababb6a80fe87a535b34027bb21e44c2e2dfbca84b58eae'
				}
			) | ForEach {
				$TestData = $_
				Mock 'Invoke-RestMethod' {$TestData.Iterations} -ParameterFilter {
					$URI -eq 'https://lastpass.com/iterations.php' -and
					$Body.email -eq $TestData.Username.ToLower()			
				}
				$Credential = [PSCredential]::New(
					$TestData.Username,
					(ConvertTo-SecureString -AsPlainText -Force $TestData.Password)
				)
				Connect-Lastpass -Credential $Credential | Out-Null
				It ('{0} - {1} iterations' -f $TestData.Username, $TestData.Iterations) {
					Assert-MockCalled 'Invoke-RestMethod' -ParameterFilter {
						$URI -eq 'https://lastpass.com/login.php' -and
						$Body.Hash -eq $TestData.Hash
					}
				} 
			}
		}

		Context 'App OTP MFA is required' {

			$OTPEnabledMockParam = @{
				CommandName = 'Invoke-RestMethod'
				ParameterFilter = { 
					$URI -eq 'https://lastpass.com/login.php'
				}   
			}
			Mock @OTPEnabledMockParam {
				Return [PSCustomObject] @{
					Response = [PSCustomObject] @{
						Error = [PSCustomObject] @{
							Cause = 'googleauthrequired'
						}
					}
				}
			}


			$OTPLoginMockParam = @{
				CommandName = 'Invoke-RestMethod'
				ParameterFilter = { 
					$URI -eq 'https://lastpass.com/login.php' -and 
					$Body.OTP
				}
			}
			Mock @OTPLoginMockParam {
				Return [PSCustomObject] @{
					Response = [PSCustomObject] @{
						OK = [PSCustomObject] @{
							UID				= '123456789'
							SessionID		= 'uu4fdsu9fsDFad9WufdFEsaUUFD'
							Token			= 'MTU0ODA0OTkxNi45MzMxLbu/wlKm16H07pJsq3q4UACWuqmr0nT+8msPiVgK4/Jv'
							PrivateKeyEnc	= 'TestPrivateKey'
						}
					}
				}
			}

			Mock 'Read-Host' {'124578'}


			Connect-Lastpass -Credential $Credential -OneTimePassword 123456 | Out-Null

			It 'Makes the initial call without the OTP call' {
				Assert-MockCalled @OTPEnabledMockParam
			}

			It 'Includes OTP code passed as a parameter without interacting with the user' {
				Assert-MockCalled Invoke-RestMethod -ParameterFilter {
					$URI -eq 'https://lastpass.com/login.php' -and 
					$Body.OTP -eq '123456'
				}
				Assert-MockCalled 'Read-Host' -Exactly -Times 0
			}
		
			Connect-Lastpass -Credential $Credential | Out-Null
			It 'Prompts user for app OTP if OTP parameter not included' {
				Assert-MockCalled 'Read-Host' -Exactly -Times 1
				Assert-MockCalled 'Invoke-RestMethod' -ParameterFilter {
					$URI -eq 'https://lastpass.com/login.php' -and 
					$Body.OTP -eq '124578'
				}
			}
		}


		Context 'Yubikey MFA required' {
			It 'Prompts for Yubikey code' {}
		}


		Context 'Sesame MFA required' {
			It 'Prompts for Sesame code' {}
			# Should this be for every login type? Switch parameter?
			#It 'Sets the device trusted if specified' {}
		}


		Context 'Out of Band MFA required' {
			It 'Prompts user to complete OOB authentication' {}

			It 'Polls the OOB endpoint to check whether authentication has succeeded' {}

			It 'Proceeds once the OOB authentication has completed' {}

		}

		
		# Errors: mock login response
		# Need context for each or just mock+call+it blocks?
		# Maybe just it with testcases? or ForEach?
		Context 'unknownemail error' {
			It 'Throws error stating username is incorrect' {}
		}

		Context 'unknownpassword error' {
			It 'Throws error stating password is incorrect' {}
		}

		Context 'verifydevice error' {
			It 'Throws error instructing user to verify location' {}
		}

		Context 'Unknown Error' {
			It 'Throws the error message' {}
		}

	}

	Describe Sync-Lastpass {

		BeforeAll {
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
			}
		}

		$DownloadMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/getaccts.php'}
		}
		Mock @DownloadMockParam { [XML] (Get-Content $ScriptRoot/Vault.xml) }

		$Result = Sync-Lastpass

		It 'Calls the download API' {
			Assert-MockCalled @DownloadMockParam
		}

		It 'Saves the blob to the module level variable' {
			$Script:Blob | Should -Not -BeNullOrEmpty
		}

		It 'Decrypts the account names' {
			@(
				'ThisIsTheAccountName',
				'SecureNote1',
				'TestName#$/3'
			) | Should -BeIn $Script:Blob.Accounts.Account.Name
		}

		It 'Outputs ?' {
			
		}

	}

	Describe New-Account {
		It 'Sets the account id to 0' -skip {
			Verify-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$Body.aid -eq '0'
			}
		}
	}

	Describe Get-Account {

		BeforeAll {
			$Script:Blob = ([XML] (Get-Content $ScriptRoot/Vault.xml)).Response
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$Script:Blob.Accounts.Account | ForEach { 
				$_.SetAttribute('name', (ConvertFrom-LPEncryptedString $_.Name))
			}
		}

		$Result = Get-Account

		It 'Returns all accounts if no account name is specified' {

			$Result.Count | Should -Be 2
			@(
				@{ ID = '1835977081662683158'; Name = 'ThisIsTheAccountName'}
				@{ ID = '6989667599733115219'; Name = 'TestName#$/3' }
			) | ForEach {
				$Item = $_
				$Result | Where {
					$_.ID -eq $Item.ID -and
					$_.Name -eq $Item.Name
				} | Should -Not -BeNullOrEmpty
			}
		}
		
		$Result = Get-Account 'ThisIsTheAccountName'
		$Now = [DateTime]::Now

		It 'Gets account by name' {
			$Result.Count | Should -Be 1
		}

		It 'Decrypts the folder' {
			$Result.Folder | Should -Be 'Productivity Tools'
		}

		It 'Decrypts the username' {
			$Result.Username | Should -Be 'ThisIsTheUsername'
		}
		
		It 'Decrypts the note content' {
			$Result.Notes | Should -Be 'These are arbitrary Notes attached to the Account'
		}
		
		It 'Exposes the last modification timestamp as a DateTime object' {
			$Result.LastModified | Should -BeOfType DateTime
			$Result.LastModified | Should -Be ([DateTime] '12/14/18 7:37:21 PM')
		}
		
		It 'Exposes the last access timestamp as a DateTime object' {
			$Result.LastAccessed | Should -BeOfType DateTime
			# $Result.LastAccessed | Should -Be ([DateTime] '1/25/19 3:09:08 AM')
		}

		It 'Updates the LastAccessed time' {
			$Result.LastAccessed.DateTime | Should -Be $Now.DateTime
		}
		
		It 'Exposes the password as a ScriptProperty' {
			($Result.PSObject.Properties | Where Name -eq 'Password').MemberType | 
				Should -Be ScriptProperty

			$Result.Password | Should -Be 'ThisIsThePassword'
		}

		It 'Accepts pipeline input' {
			$Result = 'ThisIsTheAccountName' | Get-Account
			$Result.ID | Should -Be 1835977081662683158
			$Result.PSTypeNames[0] | Should -Be 'Lastpass.Account'
		}

		It 'Prompts for master password if account is password protected' {
			($Script:Blob.Accounts.Account |
				Where Name -eq 'ThisIsTheAccountName').SetAttribute('pwprotect', 1)
			Mock Read-Host { 'Password' | ConvertTo-SecureString -A -F }
			Mock New-Key {
				[Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
			} -ParameterFilter { $Credential.GetNetworkCredential().Password -eq 'Password' }

			Get-Account 'ThisIsTheAccountName'
			
			Assert-MockCalled Read-Host
		}

		It 'Throws if master password check is wrong' {
			Mock Read-Host {'NotTheCorrectPassword' | ConvertTo-SecureString -A -F}
			{Get-Account 'ThisIsTheAccountName'} | Should -Throw
			
		}
	}

	Describe Set-Account {

		BeforeAll {
			$Script:Blob = ([XML] (Get-Content $ScriptRoot/Vault.xml)).Response
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$Script:Blob.Accounts.Account | ForEach { 
				$_.SetAttribute('name', (ConvertFrom-LPEncryptedString $_.Name))
			}
		}

		$UpdateAPIMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/show_website.php' }
			MockWith = {
				#Write-Host 'in mock'
				[XML] '<xmlresponse>
					<result 
						action="added" 
						aid="5806258868441752428" 
						urid="0" 
						msg="accountupdated" 
						acctname1="" 
						acctname2="" 
						acctname3="" 
						acctname4="" 
						acctname5="" 
						acctname6="" 
						grouping="!lRcc9xINpaUuHfd3Dt2sWZR8obQhQ==|NlyT/4wLJ4Vjfdstgxc2xVOk63eJ1dw61UURMC20vNOP8i/ImUqxiKXZ9mYjCbrmH5l" 
						count="0" 
						lasttouch="0000-00-00 00:00:00" 
						editlink="" 
						url="68747470733a2f2f676f6f676c652e636f6d" 
						fav="1" 
						launchjs="" 
						deleted="0" 
						remoteshare="0" 
						username="!6hlToUTU2WMFvNIfds4rbaFjHv2bg==|TnC0fdsar55/KwXzSH/d5+2MRA==" 
						localupdate="1" 
						accts_version="134" 
						pwprotect="1" 
						submit_id="" 
						captcha_id="" 
						custom_js="">
					</result>
				</xmlresponse>'
			}
		}
		Mock @UpdateAPIMockParam

		Mock Sync-Lastpass {}

		$Account = [PSCustomObject] @{
			ID           = '5148901049320353252'
			Name         = 'sitename'
			URL          = 'http://url.com'
			Folder       = 'NewFolder1\NewFolder2'
			Username     = 'usernamehere2'
			Credential   = [PSCredential]::New(
								'usernamehere2',
								(ConvertTo-SecureString -A -F 'fdsafdasfda')
							)
			Notes        = 'notecontent3'
			Favorite     = $False
			LastModified = [DateTime] '4/3/19 4:58:05 AM'
			LastAccessed = [DateTime] '4/4/19 1:42:48 AM'
			LaunchCount  = 0
			Bookmark     = $False
			Password     = 'fdsafdasfda'
		}

		# Test non-pipeline use case
		#$Result = Set-Account -ID $Account.ID -PasswordProtect 
		
		# $Result = $Account | Set-Account -Username 'NewUsername'

		# $Result = $Account | Set-Account -Password 'ThisIsTheNewPassword'

		# $Result = $Account | Set-Account -Name 'NewName'

		# $Result = $Account | Set-Account -URL 'https://NewURL.com'

		# $Result = $Account | Set-Account -Notes 'These are the new notes'
		#TODO: Test multiline notes

		$Result = $Account | Set-Account -Username 'NewUsername' -Password 'newPassword'


		It 'Calls the edit account API' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php'
			}
		}
		
		It 'Encrypts the Account Name' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				($Body.Name | ConvertFrom-LPEncryptedString) -eq $Account.Name
			}
		}
		
		It 'Encrypts the Username' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				($Body.UserName | ConvertFrom-LPEncryptedString) -eq 'NewUsername'
			}
		}
		
		It 'Encrypts the Password' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				($Body.Password | ConvertFrom-LPEncryptedString) -eq 'newPassword'
			}
		}
		
		It 'Encrypts the folder' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				($Body.Grouping | ConvertFrom-LPEncryptedString) -eq $Account.Folder
			}

		}
		
		It 'Encrypts the note content' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				($Body.Extra | ConvertFrom-LPEncryptedString) -eq $Account.Notes
			}

		}
		
		It 'Encodes the URL' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				
				# Write-Host $Body.URL
				$URL = (($Body.URL -split '([a-f0-9]{2})' | ForEach {
					If($_){ [Char][Convert]::ToByte($_,16) }
				}) -join '') 
				# Write-Host $URL
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$URL -eq $Account.URL
			}

		}

		It 'Resyncs accounts' {
			Assert-MockCalled Sync-Lastpass
		}

		It 'Includes password protect parameter if specified' {
			$Account | Set-Account -PasswordProtect
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$Body.PWProtect	
			} -Exactly -Times 1
		}
		
		It 'Includes favorite parameter if specified' {
			$Account | Set-Account -Favorite
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$Body.Fav	
			} -Exactly -Times 1
		}

		It 'Includes autologin parameter if specified' {
			$Account | Set-Account -AutoLogin
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$Body.AutoLogin	
			} -Exactly -Times 1
		}

		It 'Includes disable autologin parameter if specified' {
			$Account | Set-Account -DisableAutofill
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$Body.never_autofill
			} -Exactly -Times 1
		}
		
	}

	Describe Get-Note {

		BeforeAll {
			$Script:Blob = ([XML] (Get-Content $ScriptRoot/Vault.xml)).Response
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$Script:Blob.Accounts.Account | ForEach { 
				$_.SetAttribute('name', (ConvertFrom-LPEncryptedString $_.Name))
			}
		}

		$Result = Get-Note

		It 'Returns a list of all note IDs and names if no name is specified' {
			$Result.Count | Should -Be 2
			@(
				@{ ID = '7747528438954943634'; Name = 'SecureNote1' }
				@{ ID = '1439364932042364774'; Name = 'Note In Folder' }
			) | ForEach {
				$Item = $_
				$Result | Where {
					$_.ID -eq $Item.ID -and
					$_.Name -eq $Item.Name
				} | Should -Not -BeNullOrEmpty
			}

		}

		$Result = Get-Note 'Note In Folder'
		$Now = [DateTime]::Now

		It 'Returns a note by name' {
			$Result.Count | Should -Be 1
		}

		It 'Decrypts the folder' {
			$Result.Folder | Should -Be 'Productivity Tools\TestFolderName'
		}

		It 'Decrypts the note content' {
			$Result.Content | Should -Be (
				"NoteType:Server`n" +
				"Hostname:Server Note`n" +
				"Username:TestUsername`n" +
				"Password:SuperSecurePassword`n" +
				"Notes:Abitrary notes of the secure note"
			)
		}

		It 'Exposes the last modification timestamp as a DateTime object' {
			$Result.LastModified | Should -BeOfType DateTime
			$Result.LastModified | Should -Be ([DateTime] '3/26/19 12:04:29 AM')
		}
		
		It 'Exposes the last access timestamp as a DateTime object' {
			$Result.LastAccessed | Should -BeOfType DateTime
		}

		It 'Updates the LastAccessed time' {
			$Result.LastAccessed.DateTime | Should -Be $Now.DateTime
		}
	}

	Describe ConvertFrom-LPEncryptedString {
		BeforeAll {
			$Script:Session = @{
				Key = [Convert]::FromBase64String("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=")
			}
		}

		$TestCases = @(
			# Taken from https://github.com/detunized/lastpass-sharp/blob/master/test/ParserHelperTest.cs
			@{
				Encrypted = ''
				Decypted = ''
				Mode = 'ECB'
			}
			@{
				Encrypted = 'BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM='
				Decrypted = 'All your base are belong to us'
				Mode = 'ECB' #Base64
			}
			@{
				Encrypted = "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI="
				Decrypted = "All your base are belong to us"
				Mode = 'CBC' #Base64
			}
			# @{
			# 	Encrypted = "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=="
			# 	Decrypted = "All your base are belong to us"
			# 	Mode = 'CBC' #Base64
			# }
			@{
				Encrypted = "8mHxIA8rul6eq72a/Gq2iw=="
				Decrypted = "0123456789"
				Mode = 'ECB'
			}
			@{
				Encrypted = '!6TZb9bbrqpocMaNgFjrhjw==|f7RcJ7UowesqGk+um+P5ug=='
				Decrypted = '0123456789'
				Mode = 'CBC'
			}
			# @{
			# 	Encrypted = 'IQ+hiIy0vGG4srsHmXChe3ehWc/rYPnfiyqOG8h78DdX'
			# 	Decrypted = '0123456789'
			# 	Mode = 'CBC'
			# }		
		)
		It 'Secret: "<Decrypted>"; Encoding <mode>' -TestCases $TestCases {
			Param(
				[AllowEmptyString()]
				[String] $Encrypted,
				[AllowEmptyString()]
				[String] $Decrypted,
				[String] $Mode
			)
			ConvertFrom-LPEncryptedString $Encrypted | Should -Be $Decrypted
		}

		It 'Throws when invalid data is passed' {
			{ConvertFrom-LPEncryptedString 'InvalidString'} | Should -Throw
		}

		It 'Throws when no key is set' {
			$Session.Key = $Null

			{ConvertFrom-LPEncryptedString 'AnythingHere'} |
				Should -Throw 'Key not found. Please login using Connect-Lastpass.'
		}
	}

	Describe ConvertTo-LPEncryptedString {  
		BeforeAll {
			$Script:Session = @{
				Key = [Convert]::FromBase64String("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=")
			}
		}

		# The IV is randomly generated, so can't know exact output
		# will have to dynamically test using ConvertFrom-LPEncryptedString
		$TestCases = @(
			@{ Secret = '' }
			@{ Secret = 'TestValue1' }
		)
		It 'Secret: <Secret>' -TestCases $TestCases {
			Param(
				[String] $Secret
			)
			
			$Secret | ConvertTo-LPEncryptedString | ConvertFrom-LPEncryptedString |
				Should -Be $Secret
		}

		It 'Generates a different IV each time' {
			$String = 'RandomString'
			$Result1 = $String | ConvertTo-LPEncryptedString
			$Result2 = $String | ConvertTo-LPEncryptedString

			$Result1[1..24] | Should -Not -Be $Result2[1..24]
			$Result1 | ConvertFrom-LPEncryptedString |
				Should -Be ($Result2 | ConvertFrom-LPEncryptedString)
		}

		It 'Outputs the string in the correct format' {
			$Base64Regex = '(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
			'AnyString'| ConvertTo-LPEncryptedString | Should -match ('^!{0}\|{0}$' -f $Base64Regex)
		}
		
		It 'Throws when no key is set' {
			$Session.Key = $Null

			{ConvertTo-LPEncryptedString 'AnythingHere'} |
				Should -Throw 'Key not found. Please login using Connect-Lastpass.'
		}

	}

}

Describe 'Documentation Tests' {
	Get-Command -Module Lastpass | Get-Help  -ov help | ForEach {
		Describe $_.Name {
						
			It 'Has a synopsis' {
				$_.Synopsis | Should -Not -BeNullOrEmpty
				$_.Synopsis | Should -Not -Be 'Short description'
			}

			It 'Has a custom description' {
				If(!$_.Description){ Write-Warning 'No description provided' }
				$_.Description | Should -Not -Be 'Long description'
			}
			If($_.Parameters){
				It 'Has a description for each parameter' {
					$_.Parameters.Parameter | ForEach {
						If(!$_.Description){
							Throw "Parameter $($_.Name) does not have a description"
						}
					}
				}
			}
			
			If($_.Examples){
				It 'Has a description for each example' {
					If($_.Examples.Example.Count -lt 2){
						Write-Warning 'Less than 2 examples provided'
					}
					$_.Examples.Example | ForEach {
						$_.Remarks.Text[0] | ForEach {$_ | Should -Not -BeNullOrEmpty}
					}
				}
			}
		}
	}

	$Help | Out-String | Write-Verbose
}
