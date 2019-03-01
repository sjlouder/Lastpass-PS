Import-Module -Force $PSScriptRoot/Lastpass.psm1 -Verbose:$False

InModuleScope Lastpass {
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
						}
					}
				}
			}
	
		}
		Mock @LoginMockParam

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


			Connect-Lastpass -Credential $Credential -OTPCode 123456 | Out-Null

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

	Describe Sync-LastpassBlob {

		$DownloadMockParam = @{
			CommandName = 'Invoke-RestMethod'
			ParameterFilter = { $URI -eq 'https://lastpass.com/getaccts.php'}
		}
		Mock @DownloadMockParam {}

		$Result = Sync-LastpassBlob

		It 'Calls the download API' {
			Assert-MockCalled @DownloadMockParam
		}

		It 'Saves the blob to the module level variable' {

		}

		It 'Outputs ?' {
			
		}

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

	Describe Get-Account {

		BeforeAll {
			$Blob = @{}
			$Session.Key = ''
		}

		# Behave similar to Get-KeyVaultSecret?

		$Result = Get-Account

		It 'Returns all accounts if no account name is specified' {	}
		
		$Result = Get-Account 'TestAccount'

		It 'Gets account by path' {}

		It 'Decodes the Name' {}

		It 'Decrypts the group' {}

		It 'Decrypts the Username' {}
		
		It 'Decrypts the Note Content' {}
		
		It 'Exposes the last modification timestamp as a DateTime object' {}
		
		It 'Exposes the last access timestamp as a DateTime object' {}
		
		It 'Exposes the password as a ScriptProperty' {}

		It 'Prompts for password if account is password protected' {}

		It 'Accepts pipeline input' {}
	}

	Describe Set-Account {

	}


}

#Connect-Lastpass
#Multiple accounts?

#Get-Account
# Only returns password when specifically 
# Make a ScriptMethod

# Lastpass:/ drive
#	Folders
#		Accounts
#		Notes
#	Accounts (No Dolders)
#	Notes 
# Encrypted group strings are different for each account
# Might need to decrypt them all at start?


#Mass import/export


#Multiple accounts

# Reuse Existing Lpass cli

# Password generation
#	Specify allowed/disallowed characters

