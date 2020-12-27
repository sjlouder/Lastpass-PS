# Module manifest for module 'Lastpass'


@{

	# Script module or binary module file associated with this manifest.
	RootModule = 'Lastpass-PS.psm1'

	# Version number of this module.
	ModuleVersion = '0.5.0'

	# Supported PSEditions
	CompatiblePSEditions = 'Core'

	# ID used to uniquely identify this module
	GUID = 'e09bf161-b327-4200-a921-fab3a5f32a53'

	# Author of this module
	Author = 'Steven Loudermilk'

	# Company or vendor of this module
	# CompanyName = 'Unknown'

	# Copyright statement for this module
	Copyright = 'Copyright Steven Loudermilk'

	# Description of the functionality provided by this module
	Description = 'Unofficial Powershell module to interact with Lastpass.
	Built on pure Powershell/.NET core, designed to work without any other external dependencies (eg. cygwin, openSSL) to maximize cross platform portability.
	Based on https://github.com/lastpass/lastpass-cli) and https://github.com/detunized/lastpass-sharp
	For more information, check the project page: https://github.com/sjlouder/Lastpass-PS'

	# Minimum version of the PowerShell engine required by this module
	PowerShellVersion = '7.0'

	# Name of the PowerShell host required by this module
	# PowerShellHostName = ''

	# Minimum version of the PowerShell host required by this module
	# PowerShellHostVersion = ''

	# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# DotNetFrameworkVersion = ''

	# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# ClrVersion = ''

	# Processor architecture (None, X86, Amd64) required by this module
	# ProcessorArchitecture = ''

	# Modules that must be imported into the global environment prior to importing this module
	# RequiredModules = @()

	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @()

	# Script files (.ps1) that are run in the caller's environment prior to importing this module.
	# ScriptsToProcess = @()

	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @()

	# Format files (.ps1xml) to be loaded when importing this module
	# FormatsToProcess = @()

	# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
	# NestedModules = @()

	# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
	# Commenting out as the list of functions to export are determined dynamically based on module parameters
	# FunctionsToExport = @()

	# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
	CmdletsToExport = @()

	# Variables to export from this module
	VariablesToExport = @() #'*'

	# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
	AliasesToExport = @()

	# DSC resources to export from this module
	# DscResourcesToExport = @()

	# List of all modules packaged with this module
	# ModuleList = @()

	# List of all files packaged with this module
	# FileList = @()

	# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{

		PSData = @{

			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = 'Lastpass', 'PasswordManager', 'PSEdition_Core', 'Windows', 'Linux', 'MacOS'

			# A URL to the license for this module.
			LicenseUri = 'https://opensource.org/licenses/gpl-2.0.php'

			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/sjlouder/Lastpass-PS'

			# A URL to an icon representing this module.
			# IconUri = ''

			# ReleaseNotes of this module
			# ReleaseNotes = ''

			# Prerelease string of this module
			# Prerelease = ''

			# Flag to indicate whether the module requires explicit user acceptance for install/update/save
			# RequireLicenseAcceptance = $false

			# External dependent modules of this module
			# ExternalModuleDependencies = @()

		}

	}

	# HelpInfo URI of this module
	# HelpInfoURI = ''

	# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
	# DefaultCommandPrefix = 'Lastpass'

}

