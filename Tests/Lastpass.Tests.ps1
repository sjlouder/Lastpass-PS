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
				@{ ID = '1835977081662683158'; Name = 'ThisIsTheAccountName'},
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

		It 'Gets account by Name' {
			$Result.Count | Should -Be 1
		}

		It 'Decrypts the group' {
			$Result.Group | Should -Be 'Productivity Tools'
		}

		It 'Decrypts the Username' {
			$Result.Username | Should -Be 'ThisIsTheUsername'
		}
		
		It 'Decrypts the Note Content' {
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
			$Result.LastAccessed.DateTime | Should -Be ([DateTime]::Now.DateTime)
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

	}

	Describe ConvertFrom-LPEncryptedString {
		BeforeAll {
			$Session.Key = [Convert]::FromBase64String("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=")
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
	}

}
