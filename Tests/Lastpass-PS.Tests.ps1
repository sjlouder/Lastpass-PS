[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
	'PSAvoidUsingConvertToSecureStringWithPlainText', '',
	Justification = 'This uses non-sensitive test data'
)]
Param()


Import-Module -Force $PSScriptRoot/../Lastpass-PS -ArgumentList @{ Debug = $True } -Verbose:$False
InModuleScope Lastpass-PS {

	$ScriptRoot = $PSScriptRoot
	$IsInteractive = $Script:Interactive

	$Script:ParsedVault = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-JSON -AsHashtable
	$Script:DecryptedVault = Get-Content $ScriptRoot/DecryptedVault.json | ConvertFrom-JSON -AsHashtable

	# Make sure no tests actually reach out to the internet
	Mock Invoke-RestMethod {}

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
							#FIXME: This needs to be the actual value
							#PrivateKeyEnc	= 'TestPrivateKey0-324irfk49-'
							Iterations		= '100100'
							LPUsername		= 'Username'
						}
					}
				}
			}

		}
		Mock @LoginMockParam

		Mock Sync-Lastpass

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
			$Session | Should -Not -BeNullOrEmpty
			$WebSession | Should -Not -BeNullOrEmpty
			@{
				UID = '123456789'
				SessionID = 'SessionIDHere1232'
				Token = 'TokenHere12332o432i432'
				PrivateKey = [System.Security.Cryptography.RSAParameters]::New()
				Iterations = '100100'
				Username = 'Username'
			}.GetEnumerator() | ForEach {
				$Item = $_.Key
				$Session.$Item | Should -Be $_.Value
			}
			# Because the key is an array, it requires different logic
			# $Session.Key | Write-Host
			$Param = @{
				ReferenceObject = $Session.Key
				DifferenceObject = @(
					35,117,158,133,114,46,63,215,
					143,149,220,43,236,172,90,97,
					75,234,179,100,253,33,11,232,
					79,226,127,44,65,148,67,121
				)
				SyncWindow = 0
			}
			Compare-Object @Param | Should -BeNullOrEmpty
		}

		It 'Decrypts the private key' {
			$Session.PrivateKey | Should -Not -BeNullOrEmpty
			#TODO: $Session.PrivateKey | Should -Be 'ExpectedValue'
		}

		It 'Syncs the account secrets' {
			Assert-MockCalled Sync-Lastpass
		}

		It 'Skips the sync if -SkipSync parameter is specified' {
			Connect-Lastpass -Credential $Credential -SkipSync
			Assert-MockCalled Sync-Lastpass -Exactly -Times 0 -Scope It
		}

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
				# Write-Host "Session Key: $($Session.Key)"
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
					$URI -eq 'https://lastpass.com/login.php' -and
					!$Body.containsKey('otp')
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
						#	PrivateKeyEnc	= 'TestPrivateKey'
							Iterations		= '100100'
							LPUsername		= 'Username'

						}
					}
				}
			}

			Mock 'Read-Host' {'124578'}


			Connect-Lastpass -Credential $Credential -OneTimePassword 123456 | Out-Null

			It 'Attempts to log in normally' -Skip {
				Assert-MockCalled @OTPEnabledMockParam -Scope Context
			}

			It 'Includes OTP code passed as a parameter without interacting with the user' {
				Assert-MockCalled Invoke-RestMethod -ParameterFilter {
					$URI -eq 'https://lastpass.com/login.php' -and
					$Body.OTP -eq '123456'
				}
				Assert-MockCalled 'Read-Host' -Exactly -Times 0
			}

			$Script:Interactive = $True
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
			Mock Write-Host -ParameterFilter {$NoNewLine}

			$OOBEnabledMockParam = @{
				CommandName = 'Invoke-RestMethod'
				ParameterFilter = {
					$URI -eq 'https://lastpass.com/login.php' -and
					!$Body.ContainsKey('outofbandrequest')
				}
			}
			Mock @OOBEnabledMockParam {
				#$Body | Out-String | Write-Host
				Return [PSCustomObject] @{
					Response = [PSCustomObject] @{
						Error = [PSCustomObject] @{
							Cause = 'OutOfBandRequired'
							OutOfBandName = 'Duo Security'
							Capabilities = 'None'
						}
					}
				}
			}

			$OOBPollMockParam = @{
				CommandName = 'Invoke-RestMethod'
				ParameterFilter = {
					$URI -eq 'https://lastpass.com/login.php' -and
					$Body.outofbandrequest
				}
			}
			Mock @OOBPollMockParam {
				$ErrorResponse = @{
					Cause = 'OutOfBandRequired'
					OutOfBandName = 'Duo Security'
				}
				If(!$Body.ContainsKey('outofbandretryid')){
					$ErrorResponse.RetryID = 0
				}
				ElseIf($Body.outofbandretryid -eq 3){
					Return [PSCustomObject] @{
						Response = [PSCustomObject] @{
							OK = [PSCustomObject] @{
								UID				= '123456789'
								SessionID		= 'SessionIDHere1232'
								Token			= 'TokenHere12332o432i432'
								#PrivateKeyEnc	= 'TestPrivateKey0-324irfk49-'
								Iterations		= '100100'
								LPUsername		= 'Username'
							}
						}
					}
				}
				Else{
					$ErrorResponse.RetryID = $Body.outofbandretryid + 1
				}
				Return [PSCustomObject] @{
					Response = [PSCustomObject] @{
						Error = [PSCustomObject] $ErrorResponse
					}
				}

			}

			Mock Start-Sleep

			$Script:Interactive = $IsInteractive

			Connect-Lastpass -Credential $Credential | Out-Null

			It 'Attempts to log in normally' -Skip {
				Assert-MockCalled Invoke-RestMethod -ParameterFilter {
					$URI -eq 'https://lastpass.com/login.php' -and
					!$Body.ContainsKey('outofbandrequest')
				}
			}

			It 'Prompts user to complete OOB authentication' {
				Assert-MockCalled Write-Host -ParameterFilter {
					$Object -eq 'Complete multifactor authentication through Duo Security'
				}
			}

			It 'Polls the OOB endpoint to check whether authentication has succeeded' {
				Assert-MockCalled @OOBPollMockParam -Times 5
			}

			It 'Proceeds once the OOB authentication has completed' {
				$Session | Should -Not -BeNullOrEmpty
				$WebSession | Should -Not -BeNullOrEmpty
				@{
					UID = '123456789'
					SessionID = 'SessionIDHere1232'
					Token = 'TokenHere12332o432i432'
					PrivateKey = [System.Security.Cryptography.RSAParameters]::New()
					Iterations = '100100'
					Username = 'Username'
				}.GetEnumerator() | ForEach {
					$Item = $_.Key
					$Session.$Item | Should -Be $_.Value
				}
				# Because the key is an array, it requires different logic
				$Param = @{
					ReferenceObject = $Session.Key
					DifferenceObject = @(
						35,117,158,133,114,46,63,215,
						143,149,220,43,236,172,90,97,
						75,234,179,100,253,33,11,232,
						79,226,127,44,65,148,67,121
					)
					SyncWindow = 0
				}
				Compare-Object @Param | Should -BeNullOrEmpty
			}

			If($Interactive){
				Context 'OTP supported' {

					Mock @OOBEnabledMockParam {
						Return [PSCustomObject] @{
							Response = [PSCustomObject] @{
								Error = [PSCustomObject] @{
									Cause = 'OutOfBandRequired'
									OutOfBandName = 'Duo Security'
									Capabilities = 'Passcode'
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
									SessionID		= 'SessionIDHere1232'
									Token			= 'TokenHere12332o432i432'
									#FIXME: This needs to be the actual value
									#PrivateKeyEnc	= 'TestPrivateKey0-324irfk49-'
									Iterations		= '100100'
									LPUsername		= 'Username'
									}
							}
						}
					}

					Connect-Lastpass -Credential $Credential | Out-Null

					It 'prompts to complete OOB authentication or enter one time password' {
						Assert-MockCalled Write-Host -ParameterFilter {
							$NoNewLine -and
							$Object -eq ('Complete multifactor authentication through ' +
										'Duo Security or enter a one time passcode: ')
						}
					}

					It 'Polls the OOB endpoint to check whether authentication has succeeded' {
						Assert-MockCalled @OOBPollMockParam
					}

					# FIXME: Console input is read using .net class calls, so can't mock it
					It 'Reads the console for OTP input' {}
					It 'Proceeds once a valid pin is entered' {}


					It 'Uses the $OneTimePassword parameter if supplied' {
						Connect-Lastpass -Credential $Credential -OneTimePassword '12312312' | Out-Null

						# Assert-MockCalled @OOBEnabledMockParam

						Assert-MockCalled Invoke-RestMethod -ParameterFilter {
							$URI -eq 'https://lastpass.com/login.php' -and
							$Body.OTP -eq '12312312'
						}
					}
				}
			}
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

	Describe Disconnect-Lastpass {
		BeforeAll {
			$Script:WebSession = [Microsoft.Powershell.Commands.WebRequestSession]::New()
			$Script:Session = @{ Token = '112e12e2q2eq2nuif2p3hu' }
		}
		Disconnect-Lastpass

		It 'Calls the logout API' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/logout.php' -and
				$Method -eq 'Post' -and
				$WebSession -and
				$Body.Method -eq 'cli' -and
				$Body.NoRedirect -eq '1' -and
				$Body.Token -eq '112e12e2q2eq2nuif2p3hu'
			}
		}

		It 'Resets the session' {
			$Script:Session | Should -BeNullOrEmpty
		}

		It 'Resets the vault' {
			$Script:Blob | Should -BeNullOrEmpty
		}

		It 'Resets the websession' {
			$Script:WebSession | Should -BeNullOrEmpty
		}

		It 'Resets the password prompt timeout' {
			$Script:PasswordTimeout | Should -Be (New-Timespan)
		}

		It 'Resets the last password prompt time' {
			$Script:PasswordPrompt | Should -BeNullOrEmpty
		}
	}

	Describe Sync-Lastpass {

		It 'Throws if user is not logged in' {
			{Sync-Lastpass} | Should -Throw 'User session not found. Log in with Connect-Lastpass'
		}

		$Script:Session = [PSCustomObject] @{
			Key = [Byte[]] @(
				160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
				60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
			)
		}

		$DownloadMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/getaccts.php'}
		}
		Mock @DownloadMockParam {
			[Char[]][Convert]::FromBase64String((Get-Content $ScriptRoot/Vault)) -join ''
		}

		$Expected = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-Json
		$Expected.Accounts | Where  { $_.FormFields } | ForEach {
			$_.FormFields | Where Type -in 'text','password' | ForEach {
				$_.Value = $_.Value | ConvertTo-SecureString -AsPlainText -Force
			}
		}
		$Expected.SecureNotes | Where { $_.AttachmentKey } | ForEach {
			$_.AttachmentKey = $_.AttachmentKey | ConvertTo-SecureString -AsPlainText -Force
		}


		Sync-Lastpass

		It 'Calls the download API' {
			Assert-MockCalled @DownloadMockParam
		}

		It 'Saves the blob to the module level variable' {
			$Script:Blob | Should -Not -BeNullOrEmpty
		}

		It 'Parses the blob version from blob' {
			$Blob.Version | Should -Be $Expected.Version
		}

		It 'Parses the accounts' {
			$Blob.Accounts.Length | Should -Be $Expected.Accounts.Count
			$Expected.Accounts | ForEach {
				$Reference = $_
				$Account = ($Blob.Accounts | Where ID -eq $Reference.ID)
				$Account | Should -Not -BeNullOrEmpty
				Compare-Object $Reference.PSObject.Properties $Account.Keys -Property Name |
					Should -BeNullOrEmpty

				$Account.Keys |
					Where {
						$_ -notin @(
							'PSTypeName'
							'Username'
							'Password'
							'Notes'
							'Credential'
							'FormFields'
						)
					} | ForEach {
						If($Account.$_ -is [DateTime]){
							$Account.$_.DateTime | Should -Be ($Epoch.AddSeconds([Int]$Reference.$_).DateTime)
						}Else{ $Account.$_ | Should -Be $Reference.$_ -Because $_}
					}
			}
		}
		$Account = $Blob.Accounts | Where ID -eq '1835977081662683158'

		It 'Converts the last modification timestamp to a DateTime object' {
			$Account.LastModifiedGMT | Should -BeOfType DateTime
			$Account.LastModifiedGMT | Should -Be ([DateTime] '08/15/2019 4:42:38 AM')
		}

		It 'Converts the last access timestamp as a DateTime object' {
			$Account.LastAccessed | Should -BeOfType DateTime
			$Account.LastAccessed | Should -Be ([DateTime] '01/25/2019 3:09:08 AM')
		}

		It 'Parses the secure notes' {
			$Blob.SecureNotes.Length | Should -Be $Expected.SecureNotes.Count
			$Expected.SecureNotes | ForEach {
				$Reference = $_
				$Note = ($Blob.SecureNotes | Where ID -eq $Reference.ID)
				$Note | Should -Not -BeNullOrEmpty
				Compare-Object $Reference.PSObject.Properties $Note.PSObject.Properties -Property Name |
					Should -BeNullOrEmpty

				$Note.Keys | Where {
					$_ -notin @(
						'Notes'
						'PSTypeName'
						'AttachmentKey'
						'Attachments'
					)
				} | ForEach {
					If($Note.$_ -is [DateTime]){
						$Note.$_.DateTime | Should -Be ($Epoch.AddSeconds([Int]$Reference.$_).DateTime)
					}Else{ $Note.$_ | Should -Be $Reference.$_ -Because $_ }
				}
			}
		}

		It 'Parses and decrypts the folders' {
			$Blob.Folders.Length | Should -Be 4
			$Expected.Folders | ForEach {
				$Reference = $_
				# $_ | Out-String | Write-Host
				$Folder = ($Blob.Folders | Where ID -eq $Reference.ID)
				$Folder | Should -Not -BeNullOrEmpty
				Compare-Object $Reference.PSObject.Properties $Folder.Keys -Property Name |
					Should -BeNullOrEmpty

				$Folder.Keys | Where { $_ -notin 'PSTypeName' } | ForEach {
					# Write-Host $_
					# Write-Host $Folder.$_
					If($Folder.$_ -is [DateTime]){
						$Folder.$_.DateTime | Should -Be ($Epoch.AddSeconds([Int]$Reference.$_).DateTime)
					}Else{ $Folder.$_ | Should -Be $Reference.$_ -Because $_ }
				}
			}
		}

		It 'Parses the account form fields' {
			$Account = $Blob.Accounts | Where ID -eq '5148901049320353252'
			$Account.FormFields | Should -Not -BeNullOrEmpty
			$Account.FormFields | Should -BeOfType Collections.Specialized.OrderedDictionary

			$ExpectedAccount = $Expected.Accounts | Where ID -eq $Account.ID
			$ExpectedAccount.FormFields | ForEach {
				$ExpectedField = $_
				$Field = $Account.FormFields | Where Name -eq $_.Name
				$Field | Should -Not -BeNullOrEmpty -Because $_.Name
				'Name',
				'Type',
				'Checked' | ForEach {
					$Field[$_] | Should -Be $ExpectedField.$_ -Because $_
				}
			}
		}

		It 'Decrypts the non-secure form field values' {
			$Blob.Accounts | Where {$_.FormFields} | ForEach {
				$Account = $_
				$ExpectedAccount = $Expected.Accounts | Where ID -eq $Account.ID
				$Account.FormFields | Where Type -eq 'Select-one' | ForEach {
					$Field = $_
					$ExpectedField = $ExpectedAccount.FormFields | Where Name -eq $Field.Name
					$Field.Value | Should -Be $ExpectedField.Value
				}
				$Account.FormFields | Where Type -eq 'checkbox' | ForEach {
					$Field = $_
					$ExpectedField = $ExpectedAccount.FormFields | Where Name -eq $Field.Name
					$Field.Checked | Should -Be $ExpectedField.Checked
				}

			}
		}

		It 'Converts the Secure form field values to a SecureString' {
			$Blob.Accounts.FormFields | Where Type -in 'Text', 'Password' | ForEach {
				$_.Value | Should -BeOfType SecureString
			}
		}

		It 'Parses the secure note attachments' {
			$Blob.SecureNotes | Where { $_.Attachments } | ForEach {
				$Note = $_
				$ExpectedNote = $Expected.SecureNotes | Where ID -eq $Note.ID
				$Note.Attachments | ForEach {
					$Attachment = $_
					$Attachment | Should -Not -BeNullOrEmpty -Because $_.ID

					$ExpectedAttachment = $ExpectedNote.Attachments | Where ID -eq $Attachment.ID
					$Param = @{
						ReferenceObject = $ExpectedAttachment.PSObject.Properties
						DifferenceObject = $Attachment.PSObject.Properties
						Property = 'Name', 'Value'
					}
					Compare-Object @Param | Should -BeNullOrEmpty
				}
			}
		}

		It 'Parses and decrypts the shared folders' {
			$Blob.SharedFolders.Length | Should -Be 2
			$Expected.SharedFolders | ForEach {
				$Reference = $_
				$Folder = ($Blob.SharedFolders | Where ID -eq $Reference.ID)
				$Folder | Should -Not -BeNullOrEmpty
				Compare-Object $Reference.PSObject.Properties $Folder.PSObject.Properties -Property Name |
					Should -BeNullOrEmpty
				$Folder.PSObject.Properties.Name | ForEach {
					Switch($_){
						Key { [Char[]] $Folder.$_ -join '' | Should -Be $Reference.$_ }
						RSAEncryptedFolderKey {
							($Folder.$_ | ForEach { "{0:x2}" -f $_ }) -join '' |
								Should -Be $Reference.$_
						}
						Default { $Folder.$_ | Should -Be $Reference.$_ }
					}
				}
			}
		}

		It 'Outputs a Lastpass.Sync object' {}
	}

	Describe New-Account {
		It 'Throws if user is not logged in' -skip {
			$TempSession = $Script:Session
			$Script:Session = $Null
			{ New-Account } | Should -Throw 'User session not found. Log in with Connect-Lastpass'
			$Script:Session = $TempSession
		}

		It 'Sets the account id to 0' -skip {
			Verify-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$Body.aid -eq '0'
			}
		}
	}

	Describe Get-Account {

		BeforeAll {
			$Script:Blob = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-Json -AsHashtable
			$Script:Blob.Accounts | ForEach {
				$Account = $_
				'Username','Password','Notes' | ForEach {
					If($Account[$_]){$Account[$_] = ConvertTo-SecureString -A -F $Account[$_]}
				}
				If($_.FormFields){
					$_.FormFields |
						Where Type -match 'email|tel|text|password|textarea' |
						ForEach { $_.Value = $_.Value | ConvertTo-SecureString -A -F }
				}
			}
			$Script:PasswordPrompt = [DateTime]::Now
			$Script:PasswordTimeout = New-TimeSpan -Minutes 2
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$ExpectedAccounts = (Get-Content $ScriptRoot/DecryptedVault.json | ConvertFrom-Json -AsHashTable).Accounts
		}

		It 'Throws if user is not logged in' {
			$TempSession = $Script:Session
			$Script:Session = $Null
			{ Get-Account } | Should -Throw 'User session not found. Log in with Connect-Lastpass'
			$Script:Session = $TempSession
		}

		$Result = Get-Account

		It 'Returns all accounts if no account name is specified' {
			$Result.Count | Should -Be $ExpectedAccounts.Count
			@(
				@{ ID = '1835977081662683158'; Name = 'Account1' }
				@{ ID = '5148901049320353252'; Name = 'Account2' }
				@{ ID = '3656362581793908418'; Name = 'SiteShareTest' }
				@{ ID = '3524762968710500297'; Name = 'ShareAccount1' }
				@{ ID = '6274670822055333050'; Name = 'TestName#$/3' }
			) | ForEach {
				$Item = $_
				$Result | Where {
					$_.ID -eq $Item.ID -and
					$_.Name -eq $Item.Name
				} | Should -Not -BeNullOrEmpty
			}
		}

		$Expected = $ExpectedAccounts | Where Name -eq 'Account1'
		$Result = Get-Account 'Account1'
		$Now = [DateTime]::Now

		It 'Gets account by name' {
			$Result.Count | Should -Be 1
		}

		It 'Returns a Lastpass Account Object' {
			$Result | Should -BeOfType "PSCustomObject('Lastpass.Account')"
		}

		It 'Decrypts the username' {
			$Result.Username | Should -Be $Expected.Username
		}

		It 'Decrypts the password' {
			$Result.Password | Should -Be $Expected.Password
		}

		It 'Decrypts the note content' {
			$Result.Notes | Should -Be $Expected.Notes
		}

		It 'Decrypts and exposes the form fields' {
			$Result = Get-Account 'Account2'
			$Expected = $ExpectedAccounts | Where Name -eq 'Account2'
			$Result.FormFields | Should -Not -BeNullOrEmpty
			$Result.FormFields | Should -BeOfType "PSCustomObject('Lastpass.FormField')"
			$Expected.FormFields.Keys | ForEach {
				$FieldName = $_
				$Result.FormFields[$_] | Should -Be $Expected.FormFields[$_] -Because $FieldName
			}
		}

		It 'Updates the LastAccessed time' {
			$Result.LastAccessed.DateTime | Should -Be $Now.DateTime
		}

		It 'Accepts pipeline input' {
			$Result = 'Account1' | Get-Account
			$Result | Should -BeOfType "PSCustomObject('Lastpass.Account')"
			$Result.ID | Should -Be 1835977081662683158
		}

		It 'Prompts for master password if account is password protected' {
			($Script:Blob.Accounts |
				Where Name -eq 'Account1').PasswordProtect = $True
			Mock Confirm-Password
			Get-Account 'Account1'

			Assert-MockCalled Confirm-Password
		}

		It 'Creates a PSCredential property' {
			$Result.Credential | Should -Not -BeNullOrEmpty
			$Result.Credential | Should -BeOfType PSCredential
			$Result.Credential.Username | Should -Be $Expected.Username
			$Result.Credential.GetNetworkCredential().Password | Should -Be $Expected.Password
		}

		It 'Filters out duplicate accounts with the same name' {
			$ExpectedCount = ($ExpectedAccounts | Where Name -eq 'Duplicate Name').Count
			$Result = Get-Account 'Duplicate Name' | Get-Account
			$Result.Count | Should -Be $ExpectedCount
		}
	}

	Describe Set-Account {

		Mock Set-Item

		$Account = [PSCustomObject] @{
			PSTypeName	 = 'Lastpass.Account'
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

		It 'Throws if user is not logged in' {
			$TempSession = $Script:Session
			$Script:Session = $Null
			{ $Account | Set-Account } | Should -Throw 'User session not found. Log in with Connect-Lastpass'
			$Script:Session = $TempSession
		}

		$Account | Set-Account
		It 'Calls Set-Item with the parameters passed to it' {
			Assert-MockCalled Set-Item -ParameterFilter {
				$ID			-eq '5148901049320353252' -and
				$Name		-eq 'sitename' -and
				$Folder		-eq 'NewFolder1\NewFolder2' -and
				$URL		-eq 'http://url.com' -and
				$Credential -eq $Account.Credential -and
				$Notes		-eq 'notecontent3' -and
				!$Favorite	-and
				!$AutoLogin	-and
				!$DisableAutofill
			}
		}
		$Account | Add-Member -Type NoteProperty -Name ShareID -Value 10249432

		It 'Includes the ShareID if the account is shared' {
			$Account | Set-Account
			Assert-MockCalled Set-Item -Scope It -ParameterFilter {
				$ID				-eq '5148901049320353252' -and
				$Name			-eq 'sitename' -and
				$Folder			-eq 'NewFolder1\NewFolder2' -and
				$ShareID		-eq 10249432 -and
				$URL			-eq 'http://url.com' -and
				$Credential 	-eq $Account.Credential -and
				$Notes			-eq 'notecontent3' -and
				!$Favorite		-and
				!$AutoLogin		-and
				!$DisableAutofill
			}
		}
	}

	Describe Get-Note {

		BeforeAll {
			$Script:Blob = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-Json -AsHashtable
			$Script:Blob.SecureNotes | ForEach {
				$_.Notes = ConvertTo-SecureString -A -F $_.Notes
				If($_.Attachments){
					$_.Attachments | ForEach {
						$_.FileName = $_.FileName | ConvertTo-SecureString -A -F
					}
				}
			}
			$Script:Blob.SharedFolders | ForEach { $_.Key = [Byte[]][Char[]] $_.Key }
			$Script:PasswordPrompt = [DateTime]::Now
			$Script:PasswordTimeout = New-TimeSpan -Minutes 2
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$ExpectedNotes = (Get-Content $ScriptRoot/DecryptedVault.json | ConvertFrom-Json).SecureNotes
		}

		It 'Throws if user is not logged in' {
			$TempSession = $Script:Session
			$Script:Session = $Null
			{ Get-Note } | Should -Throw 'User session not found. Log in with Connect-Lastpass'
			$Script:Session = $TempSession
		}

		$Result = Get-Note

		It 'Returns a list of all note IDs and names if no name is specified' {
			$Result.Count | Should -Be $ExpectedNotes.Count
			$ExpectedNotes | Select ID, Name | ForEach {
				$Item = $_
				$Result | Where {
					$_.ID -eq $Item.ID -and
					$_.Name -eq $Item.Name
				} | Should -Not -BeNullOrEmpty -Because $Item.Name
			}
		}

		$Expected = $ExpectedNotes | Where Name -eq 'Attachment Test'
		$Result = Get-Note 'Attachment Test'
		$Now = [DateTime]::Now

		It 'Returns a note by name' {
			$Result.Count | Should -Be 1
		}

		It 'Returns a Lastpass Note Object' {
			$Result | Should -BeOfType "PSCustomObject('Lastpass.SecureNote')"
		}

		It 'Decrypts the note content' {
			$Result.Notes | Should -Be $Expected.Notes
		}

		It 'Decrypts the Attachment file names' {
			$Result | Where { $_.Attachments } | ForEach {
				$Note = $_
				$ReferenceNote = $ExpectedNotes | Where ID -eq $Note.ID
				$ReferenceNote | Should -Not -BeNullOrEmpty
				$_.Attachments | ForEach {
					$Attachment = $_
					$ReferenceAttachment = $ReferenceNote.Attachments | Where ID -eq $Attachment.ID
					$ReferenceAttachment | Should -Not -BeNullOrEmpty
					$Attachment.FileName | Should -Be $ReferenceAttachment.FileName
				}
			}
		}

		It 'Updates the LastAccessed time' {
			$Result.LastAccessed.DateTime | Should -Be $Now.DateTime
		}

		# Custom note
		$Result = Get-Note 'Note In Folder'
		$Expected = $ExpectedNotes | Where Name -eq 'Note In Folder'
		It 'Prompts for password if note is password protected' {
			($Script:Blob.SecureNotes |
				Where Name -eq 'Attachment Test').PasswordProtect = $True
			Mock Confirm-Password
			Get-Note 'Attachment Test'

			Assert-MockCalled Confirm-Password
		}

		It 'Parses custom note properties and exposes them as an ordered hashtable' {
			$Result.Notes | Should -Not -BeNullOrEmpty
			$Result.Notes | Should -BeOfType Collections.Specialized.OrderedDictionary
			$Result.NoteType | Should -Be $Expected.NoteType

			'Hostname',
			'Username',
			'Password',
			'Notes' | ForEach {
				$Result.Notes.$_ | Should -Be $Expected.Notes.$_ -Because $_
			}

		}

		It 'Filters out duplicate notes with the same name' {
			$ExpectedCount = ($ExpectedNotes | ? Name -eq 'Duplicate Note').Count
			$Result = Get-Note 'Duplicate Note' | Get-Note
			$Result.Count | Should -Be $ExpectedCount
		}

	}

	Describe Set-Note {

		Mock Set-Item

		$Note = [PSCustomObject] @{
			PSTypeName	 = 'Lastpass.SecureNote'
			ID           = '5148901049320353252'
			Name         = 'sitename'
			Notes	     = 'notecontent3'
			Folder       = 'NewFolder1\NewFolder2'
			Favorite     = $False
			LastModified = [DateTime] '4/3/19 4:58:05 AM'
			LastAccessed = [DateTime] '4/4/19 1:42:48 AM'
		}

		It 'Throws if user is not logged in' {
			$TempSession = $Script:Session
			$Script:Session = $Null
			{ $Note | Set-Note } | Should -Throw 'User session not found. Log in with Connect-Lastpass'
			$Script:Session = $TempSession
		}

		$Note | Set-Note

		It 'Calls Set-Item with the SecureNote parameter' {
			Assert-MockCalled Set-Item -ParameterFilter {
				$ID		-eq '5148901049320353252' -and
				$Name	-eq 'sitename' -and
				$Notes	-eq 'notecontent3' -and
				$Folder	-eq 'NewFolder1\NewFolder2' -and
				!$PasswordProtect -and
				!$Favorite
			}
		}

		$Note | Add-Member -Type NoteProperty -Name ShareID -Value 10249432

		It 'Includes the ShareID if the SecureNote is shared' {
			$Note | Set-Note
			Assert-MockCalled Set-Item -Scope It -ParameterFilter {
				$ID			-eq '5148901049320353252' -and
				$Name		-eq 'sitename' -and
				$ShareID	-eq 10249432 -and
				$Notes		-eq 'notecontent3' -and
				$Folder		-eq 'NewFolder1\NewFolder2' -and
				!$PasswordProtect -and
				!$Favorite
			}
		}

		$Note.Notes = [Ordered] @{
			Name = 'Note'
			NoteType = 'Test'
			IP = '127.0.0.1'
		}

		It 'Encodes the custom notes' {
			$Note | Set-Note
			Assert-MockCalled Set-Item -Scope It -ParameterFilter {
				$Notes -eq "Name:Note`nNoteType:Test`nIP:127.0.0.1`n"
			}
		}
	}

	Describe Get-Attachment {

		BeforeAll {
			$Script:Blob = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-Json -AsHashtable
			$Script:Blob.SecureNotes | ForEach {
				$_.Notes = ConvertTo-SecureString -A -F $_.Notes
				If($_.Attachments){
					$_.Attachments | ForEach {
						$_.FileName = $_.FileName | ConvertTo-SecureString -A -F
					}
				}
			}
			$Script:Blob.SharedFolders | ForEach { $_.Key = [Byte[]][Char[]] $_.Key }
			$Script:PasswordPrompt = [DateTime]::Now
			$Script:PasswordTimeout = New-TimeSpan -Minutes 2
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$ExpectedNotes = (Get-Content $ScriptRoot/DecryptedVault.json | ConvertFrom-Json).SecureNotes
		}


		Mock Get-Note {
			$Note = $DecryptedVault.SecureNotes | Where ID -eq 3365236279341564432
			If($Note.AttachmentKey -is 'String'){
				$Note.AttachmentKey = $Note.AttachmentKey | ConvertFrom-Hex
			}
			$Note.ShareID = 2321
			$Note
		}
		Mock Invoke-RestMethod { Get-Content $ScriptRoot/Attachment }
		Mock Read-Host {''}

		$AttachmentMetadata = $DecryptedVault.SecureNotes.Attachments |
			Where ID -eq 3365236279341564432-48085
		$AttachmentMetadata = [PSCustomObject] @{
			PSTypeName	= 'Lastpass.Attachment'
			ID			= $AttachmentMetadata.ID
			MIMEType	= $AttachmentMetadata.MIMEType
			StorageKey	= $AttachmentMetadata.StorageKey
			Size		= $AttachmentMetadata.Size
			FileName	= $AttachmentMetadata.FileName
		}

		It 'Throws if user is not logged in' {
			$TempSession = $Script:Session
			$Script:Session = $Null
			{ $AttachmentMetadata | Get-Attachment -FilePath TestDrive:/Attachment.txt } | Should -Throw 'User session not found. Log in with Connect-Lastpass'
			$Script:Session = $TempSession
		}

		$R = $AttachmentMetadata | Get-Attachment -FilePath TestDrive:/Attachment.txt

		It 'Appends the share ID to the api parameters if the note is shared' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/getattach.php' -and
				$Body.sharedfolderid -eq '2321'
			}
		}

		It 'Downloads the attachment from Lastpass server' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/getattach.php' -and
				$Body.GetAttach -eq '100000048085'
			}
		}

		It 'Appends the attachment filename if the specified path is a folder' {
			$R = $AttachmentMetadata | Get-Attachment -FilePath TestDrive:/
			$R.FullName | Should -Be ('{0}LPTestFile.txt' -f (Convert-Path TestDrive:/))
		}

		It 'Returns the file object' {
			$R | Should -Not -BeNullOrEmpty
			$R | Should -BeOfType 'System.IO.FileInfo'
		}

		It 'Saves the file to the specified Path' {
			$R | Should -Exist
		}

		It 'Decrypts the attachment' {
			$Reference = Get-Item $ScriptRoot/DecryptedAttachment.txt
			$ReferenceHash = $Reference | Get-FileHash
			($R | Get-FileHash).Hash | Should -Be $ReferenceHash.Hash
		}

		New-Item -Force TestDrive:/Attachment.txt
		$R = $AttachmentMetadata | Get-Attachment -FilePath TestDrive:/Attachment.txt

		It 'Prompts the user to overwrite an existing file' {
			Assert-MockCalled Read-Host
		}

		It 'Returns if the user chooses not to overwrite the file' {
			$R | Should -BeNullOrEmpty
		}

		It 'Does not prompt if -Force is specified' {
			$R = $AttachmentMetadata | Get-Attachment -FilePath TestDrive:/Attachment.txt -Force
			Assert-MockCalled Read-Host -Exactly -Times 0 -Scope It
			$R | Should -Not -BeNullOrEmpty
			$R | Should -BeOfType 'System.IO.FileInfo'
		}

		Mock ConvertFrom-LPEncryptedData { Throw 'error' }
		It 'Throws if an error occurs during attachment decryption' {
			{ $AttachmentMetadata | Get-Attachment -FilePath TestDrive:\Attachment.txt } |
				Should -Throw 'Failed to decrypt attachment'
		}

		Mock Invoke-RestMethod { Throw 'Invalid request' }
		It 'Throws if an error occurs during attachment download' {
			{ $AttachmentMetadata | Get-Attachment -FilePath TestDrive:\Attachment.txt } |
				Should -Throw 'Failed to download attachment from Lastpass server'
		}

		Mock Get-Note {
			[PSCustomObject] @{
				ID = 3365236279341564432
				Name = 'Missing AttachmentKey'
				ShareID = 2321
			}
		}
		It 'Throws if it is unable to find the attachment key' {
			{ $AttachmentMetadata | Get-Attachment -FilePath TestDrive:\Attachment.txt } |
				Should -Throw 'Unable to find attachment key'
		}

	}

	Describe New-Password {

		It 'Returns a SecureString' {
			New-Password | Should -BeOfType SecureString
		}

		It 'Returns a password of a specified length' {
			(New-Password -Length 12 -AsPlainText).Length | Should -Be 12
		}

		It 'Does not include invalid characters' {
			$Password = New-Password -AsPlainText -InvalidCharacters "A-Za-z1-9``~!@#$%^&*()\-_=+[{\]}\\|;:'`",<.>/? "
			[Char[]] $Password | ForEach {
				$_ | Should -Be ([Char] '0')
			}
		}

		It 'Only includes valid characters' {
			$ValidCharacters = [Char[]] "ABCDEFhijkll"
			$Password = New-Password -AsPlainText -ValidCharacters "A-Fh-l"
			[Char[]] $Password | ForEach {
				$_ | Should -BeIn $ValidCharacters
			}
		}

		@{
			Alphanumeric = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
			Alphabetic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
			UpperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
			LowerCase = 'abcdefghijklmnopqrstuvwxyz'
			Numeric = '0123456789'
			Base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
			XML = (
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
				"0123456789``~!@#$%^&*()-_=+[{]}\|;:,./? "
			)
		}.GetEnumerator() | ForEach {
			$ValidCharacters = [Char[]]$_.Value
			It "Filters valid characters for the $($_.Key) character set" {
				$Password = New-Password -AsPlainText -CharacterSet $_.Key
				([Char[]]$Password) | ForEach {
					$_ | Should -BeIn $ValidCharacters
				}
			}
		}

		It 'Outputs a plaintext string if -AsPlainText is specified' {
			New-Password -AsPlainText | Should -BeOfType String
		}
	}

	Describe Set-Item {
		BeforeAll {
			$Script:Blob = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-Json -AsHashtable
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
			$Script:Blob.SharedFolders | % {$_.Key = [Byte[]][Char[]] $_.Key}
			$Confirm = $ConfirmPreference
			$ConfirmPreference = 'None'
		}

		$UpdateAPIMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/show_website.php' }
			MockWith = {
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
			PSTypeName	 = 'Lastpass.Account'
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
		# Set-Account -ID $Account.ID -Name 'NoteName' -PasswordProtect
		#TODO: Test multiline notes
		#TODO: Test incomplete account/parameters
		#TODO: Shared item

		$Credential = [PSCredential]::New(
			'NewUsername',
			(ConvertTo-SecureString -A -F 'NewPassword')
		)

		$Result = $Account | Set-Item -Credential $Credential


		It 'Calls the edit account API' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$URI -eq 'https://lastpass.com/show_website.php'
			}
		}

		It 'Encrypts the Account Name' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				($Body.Name | ConvertFrom-LPEncryptedData -Base64) -eq $Account.Name
			}
		}

		It 'Encrypts the Username' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				($Body.UserName | ConvertFrom-LPEncryptedData -Base64) -eq 'NewUsername'
			}
		}

		It 'Encrypts the Password' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				($Body.Password | ConvertFrom-LPEncryptedData -Base64) -eq 'newPassword'
			}
		}

		It 'Encrypts the folder' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				($Body.Grouping | ConvertFrom-LPEncryptedData -Base64) -eq $Account.Folder
			}

		}

		It 'Encrypts the note content' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				($Body.Extra | ConvertFrom-LPEncryptedData -Base64) -eq $Account.Notes
			}

		}

		It 'Encodes the URL' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Body.URL -eq '687474703a2f2f75726c2e636f6d'
			}
		}
		#TODO: Refactor FormFields to be PSCustomObject instead of dict
		It 'Encodes the form fields' {
			$FormFields = @(
				@{ Name = 'email';		Type = 'email'; 		Value = 'email@address.com' }
				@{ Name = 'phone';		Type = 'tel'; 			Value = '1234567890' }
				@{ Name = 'username';	Type = 'text'; 			Value = 'test' }
				@{ Name = 'password';	Type = 'password'; 		Value = 'hardtoguess' }
				@{ Name = 'feedback';	Type = 'textarea'; 		Value = 'lots of text here' }
				@{ Name = 'which'; 	 	Type = 'select-one';	Value = 'selected' }
				@{ Name = 'remember';	Type = 'checkbox';		Checked = $True }
				@{ Name = 'yes_or_no';	Type = 'radio';			Checked = $False }
			) | ForEach {
				$_.PSTypeName = 'Lastpass.FormField'
				[PSCustomObject] $_
			}

			$Account | Set-Item -FormFields $FormFields
			Assert-MockCalled Invoke-RestMethod -Scope It -ParameterFilter {
				$FormString = (([Char[]] ($Body.Data | ConvertFrom-Hex)) -join '') -split "`n"
				# $FormString | Write-Host
				$URI -eq 'https://lastpass.com/show_website.php' -and
				$FormString[0] -match "0`temail`temail`t" -and
				$FormString[1] -match "0`tphone`ttel`t" -and
				$FormString[2] -match "0`tusername`ttext`t" -and
				$FormString[3] -match "0`tpassword`tpassword`t" -and
				$FormString[4] -match "0`tfeedback`ttextarea`t" -and
				$FormString[5] -match "0`twhich`tselect-one`tselected" -and
				$FormString[6] -match "0`tremember`tcheckbox`t-1" -and
				$FormString[7] -match "0`tyes_or_no`tradio`t-0" -and
				$FormString[8] -match "0`taction`t`taction" -and
				$FormString[9] -match "0`tmethod`t`tmethod"
			}
		}

		It 'Resyncs accounts' {
			Assert-MockCalled Sync-Lastpass
		}

		It 'Includes password protect parameter if specified' {
			$Account | Set-Account -PasswordProtect
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Body.PWProtect
			} -Exactly -Times 1
		}

		It 'Includes favorite parameter if specified' {
			$Account | Set-Account -Favorite
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Body.Fav
			} -Exactly -Times 1
		}

		It 'Includes autologin parameter if specified' {
			$Account | Set-Account -AutoLogin
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Body.AutoLogin
			} -Exactly -Times 1
		}

		It 'Includes disable autologin parameter if specified' {
			$Account | Set-Account -DisableAutofill
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Body.never_autofill
			} -Exactly -Times 1
		}

		It 'Returns the updated account' -Skip {
			$Result | Should -BeOfType 'Lastpass.Account'
			$Result.Username | Should -Be 'NewUsername'
			$Result.Password | Should -Be 'newPassword'
		}


		Context 'Shared Account' {
			Mock ConvertTo-LPEncryptedString { $Value }
			Mock Invoke-RestMethod { $Body | Write-Information }
			$Account | Add-Member -MemberType 'NoteProperty' -Name 'ShareID' -Value $Blob.SharedFolders[0].ID
			$Account.Folder = 'SharedFolder\{0}' -f $Account.Folder

			$Account | Set-Account

			It 'Includes the sharedfolderid parameter' {
				Assert-MockCalled Invoke-RestMethod -Scope Context -ParameterFilter {
					$Body.SharedFolderID -eq $Blob.SharedFolders[0].ID
				}
			}

			It 'Strips the Shared folder name from the folder property' {
				Assert-MockCalled ConvertTo-LPEncryptedString -Scope Context -ParameterFilter {
					$Value -eq 'NewFolder1\NewFolder2'
				}
			}

			It 'Uses the shared folder key to encrypt the account information' {
				Assert-MockCalled ConvertTo-LPEncryptedString -ParameterFilter {
					([String] $Key) -eq ([String]$Blob.SharedFolders[0].Key) -and
					$Value -eq $Account.Name
				}
				Assert-MockCalled ConvertTo-LPEncryptedString -ParameterFilter {
					([String] $Key) -eq ([String]$Blob.SharedFolders[0].Key) -and
					$Value -eq 'NewFolder1\NewFolder2'
				}
				Assert-MockCalled ConvertTo-LPEncryptedString -ParameterFilter {
					([String] $Key) -eq ([String]$Blob.SharedFolders[0].Key) -and
					$Value -eq $Account.Notes
				}
				Assert-MockCalled ConvertTo-LPEncryptedString -ParameterFilter {
					([String] $Key) -eq ([String]$Blob.SharedFolders[0].Key) -and
					$Value -eq $Account.Username
				}
				Assert-MockCalled ConvertTo-LPEncryptedString -ParameterFilter {
					([String] $Key) -eq ([String]$Blob.SharedFolders[0].Key) -and
					$Value -eq $Account.Password
				}
			}

			It 'Throws if the share is readonly' {
				$Blob.SharedFolders[0].ReadOnly = $True
				{ $Account | Set-Account } | Should -Throw 'Account sitename is in a read-only shared folder'
			}


		}
		#LastAccessed/LastModified?

		$Note = [PSCustomObject] @{
			ID           = '5148901049320353252'
			Name         = 'sitename'
			Content      = 'notecontent3'
			Folder       = 'NewFolder1\NewFolder2'
			Favorite     = $False
			LastModified = [DateTime] '4/3/19 4:58:05 AM'
			LastAccessed = [DateTime] '4/4/19 1:42:48 AM'
		}

		$Note | Set-Item -SecureNote

		It 'Sets the URL for SecureNotes to "http://sn"' {
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Body.URL -eq '687474703a2f2f736e'
			}
		}

		AfterAll { $ConfirmPreference = $Confirm }
	}

	Describe ConvertFrom-LPEncryptedData {
		BeforeAll {
			$Script:Session = @{
				Key = [Convert]::FromBase64String("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=")
			}
		}
		Mock Write-Error

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
				Mode = 'ECB'
			}
			@{
				Encrypted = "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI="
				Decrypted = "All your base are belong to us"
				Mode = 'CBC'
			}
			@{
				Encrypted = "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=="
				Decrypted = "All your base are belong to us"
				Mode = 'CBC'
			}
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
			@{
				Encrypted = 'IQ+hiIy0vGG4srsHmXChe3ehWc/rYPnfiyqOG8h78DdX'
				Decrypted = '0123456789'
				Mode = 'CBC'
			}
		)
		It 'Secret: "<Decrypted>"; Encoding <mode>' -TestCases $TestCases {
			Param(
				[AllowEmptyString()]
				[String] $Encrypted,
				[AllowEmptyString()]
				[String] $Decrypted,
				[String] $Mode
			)

			,([Char[]] $Encrypted) | ConvertFrom-LPEncryptedData -Base64 | Should -Be $Decrypted
		}

		It 'Uses the specified key if passed' {
			$Key = [Convert]::FromBase64String('Bg0kRH2p+IC4mjRHlNm/IyNnfudsEXaaPLgHDeU0NTs=')

			'IVdYT0McSfObWOy68igNDsDDSoATbUwNSt/TFEMnu5hV' |
				ConvertFrom-LPEncryptedData -Key $Key -Base64 | Should -Be 'passw'
		}

		It 'Throws when invalid data is passed' {
			{ConvertFrom-LPEncryptedData 'InvalidString'} | Should -Throw
		}

		It 'Throws when no key is set' {
			$Session.Key = $Null

			{ConvertFrom-LPEncryptedData 'AnythingHere'} |
				Should -Throw 'No decryption key found.'
		}
	}

	Describe ConvertTo-LPEncryptedString {
		BeforeEach {
			$Script:Session = @{
				Key = [Convert]::FromBase64String("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=")
			}
		}

		# The IV is randomly generated, so can't know exact output
		# will have to dynamically test using ConvertFrom-LPEncryptedData
		$TestCases = @(
			@{ Secret = '' }
			@{ Secret = 'TestValue1' }
		)
		It 'Secret: <Secret>' -TestCases $TestCases {
			Param(
				[String] $Secret
			)

			$Secret | ConvertTo-LPEncryptedString | ConvertFrom-LPEncryptedData -Base64 |
				Should -Be $Secret
		}

		It 'Uses the specified key if passed' {
			$Key = [Convert]::FromBase64String('Bg0kRH2p+IC4mjRHlNm/IyNnfudsEXaaPLgHDeU0NTs=')

			'test' | ConvertTo-LPEncryptedString -Key $Key | ConvertFrom-LPEncryptedData -Key $Key -Base64 |
				Should -Be 'test'
		}

		It 'Generates a different IV each time' {
			$String = 'RandomString'
			$Result1 = $String | ConvertTo-LPEncryptedString
			$Result2 = $String | ConvertTo-LPEncryptedString

			$Result1[1..24] | Should -Not -Be $Result2[1..24]
			$Result1 | ConvertFrom-LPEncryptedData -Base64 |
				Should -Be ($Result2 | ConvertFrom-LPEncryptedData -Base64)
		}

		It 'Outputs the string in the correct format' {
			$Base64Regex = '(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
			'AnyString'| ConvertTo-LPEncryptedString | Should -match ('^!{0}\|{0}$' -f $Base64Regex)
		}

		It 'Throws when no key is set' {
			$Session.Key = $Null

			{ConvertTo-LPEncryptedString 'AnythingHere'} |
				Should -Throw 'No decryption key found.'
		}

		Context 'SecureString ParameterSet' {
			It 'Secret: <Secret>' -TestCases $TestCases {
				Param(
					[String] $Secret
				)

				$Converted = ConvertTo-LPEncryptedString -Bytes ([Byte[]][Char[]] $Secret)
				$Converted | Should -BeOfType SecureString
				[PSCredential]::New('user', $Converted).GetNetworkCredential().Password |
					Should -Be $Secret
			}
		}

	}

	Describe Confirm-Password {
		BeforeAll {
			$Script:Blob = Get-Content $ScriptRoot/ParsedVault.json | ConvertFrom-Json -AsHashtable
			$Script:Session = [PSCustomObject] @{
				Key = [Byte[]] @(
					160,143,117,193,122,157,146,7,23,206,62,167,167,182,117,117,
					60,118,172,154,146,119,36,238,73,80,241,107,95,3,40,236
				)
				Username = 'Username'
				Iterations = '1'
			}
		}

		Mock Read-Host {'Password' | ConvertTo-SecureString -AsPlainText -Force }
		Mock New-Key { $Script:Session.Key }

		It 'Prompts for master password if password was last entered later than timeout' {
			$Script:PasswordTimeout = New-TimeSpan

			Confirm-Password
			Assert-MockCalled Read-Host -ParameterFilter {
				$AsSecureString -and $Prompt -eq  'Please confirm your password'
			}
		}

		It 'Skips check if last password check is within timeout' {
			$Script:PasswordTimeout = New-TimeSpan -Minutes 5
			$Script:PasswordPrompt = [DateTime]::Now.AddMinutes(-1)
			$ExpectedPasswordPrompt = $Script:PasswordPrompt

			Confirm-Password
			Assert-MockCalled Read-Host -Exactly -Times 0 -Scope It
			$Script:PasswordPrompt | Should -Be $ExpectedPasswordPrompt
		}

		It 'Updates the last password verification time if successful' {
			$Script:PasswordTimeout = New-TimeSpan
			$Script:PasswordPrompt = [DateTime]::Now.AddMinutes(-1)

			Confirm-Password
			Assert-MockCalled Read-Host -Exactly -Times 1 -Scope It
			Assert-MockCalled New-Key -Exactly -Times 1 -Scope It
			$Script:PasswordPrompt.Datetime | Should -Be ([DateTime]::Now).Datetime
		}

		It 'Throws if master password check is wrong' {
			$Script:PasswordTimeout = New-Timespan
			Mock New-Key { [Byte[]]::New(4) }
			{ Confirm-Password } | Should -Throw 'Password confirmation failed'
		}

	}

}

Describe 'Documentation Tests' -Tag Documentation {
	Get-Command -Module Lastpass | Get-Help | Where ModuleName -eq 'Lastpass' | ForEach {
		Describe $_.Name {

			It 'Has a synopsis' {
				$_.Synopsis | Should -Not -BeNullOrEmpty
				$_.Synopsis | Should -Not -MatchExactly ('^\s{0}\s$' -f $_.Name)
				$_.Synopsis | Should -Not -Be 'Short description'
			}

			It 'Has a custom description' {
				If(!$_.Description){ Write-Warning 'No description provided' }
				$_.Description | Should -Not -Be 'Long description'
			}
			If($_.Parameters){
				It 'Has a description for each parameter' {
				$_.Parameters.Parameter | Where { $_.Name -notin 'WhatIf', 'Confirm' } | ForEach {
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
}

Describe 'TypeData' {
	@{
		'Lastpass.Account' = @(
			'Name'
			'Username'
			'Folder'
			'Favorite'
		)
		'Lastpass.SecureNote' = @(
			'Name'
			'Folder'
			'Favorite'
		)
		'Lastpass.Folder' = @(
			'Name'
			'LastModifiedGMT'
			'LastPasswordChange'
		)
		'Lastpass.SharedFolder' = @(
			'Name'
			'ReadOnly'
		)
	}.GetEnumerator() | ForEach {
		Describe $_.Key {
			$DisplayProperties = (Get-TypeData $_.Key).DefaultDisplayPropertySet.ReferencedProperties

			$_.Value | ForEach {
				It "Displays $_ by default" {
					$_ | Should -BeIn $DisplayProperties
				}
			}
		}
	}
}


Describe 'Publishing' {
	BeforeAll {
		$Repo = (New-Item -ItemType Directory TestDrive:/PSRepo).PSPath

		$Param = @{
			Name = 'PesterRepo'
			SourceLocation = $Repo
			InstallationPolicy = 'Trusted'
			PackageManagementProvider = 'NuGet'
		}
		Register-PSRepository @Param -Verbose:$False
	}

	It 'can be published locally using Publish-Module' {
		Publish-Module -Repository PesterRepo -Path $PSScriptRoot/../Lastpass-PS -Verbose:$False -EA Stop
		Find-Module Lastpass-PS -Repository PesterRepo -Verbose:$False | Should -Not -BeNullOrEmpty
	}

	AfterAll {
		Unregister-PSrepository -Name $Param.Name -Verbose:$False
		Remove-Item -Force -Recurse TestDrive:/PSRepo -EA Silent
	}
}