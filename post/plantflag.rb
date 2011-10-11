##
# $Id: plantflag.rb xxxx 2011-10-03 Michael Boyd $
##

##
#
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post
	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Plant a Flag",
			'Description'          => %q{
				This module will plant a flag in a remote directory. The flag 
		    can either be in plain view, or hidden in an Alternate Data Stream(ADS).
		    If the flag is not to be hidden, do not set the REMOTEFILE option.
				},
			'License'              => MSF_LICENSE,
			'Version'              => '$Revision: xxxx $',
			'Platform'             => ['windows'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['Michael Boyd <denied39[at]gmail.com>']
		))
		register_options(
			[
				OptString.new('REMOTEFILE', [false, 'File name to hide flag in' ]),
				OptString.new('REMOTEDIR', [true, 'Directory to plant flag' ]),
				OptBool.new('HIDE', [false, 'Hide flag', false]),
			], self.class)

	end

	def hide_flag(rfile, flagname)
		h = @session.sys.process.execute("cmd.exe /c type #{flagname} > #{rfile}:#{flagname}", nil, {'Hidden' => true})
		print_status("Removing flag file (hidden flag is still on file system)")
		h = @session.sys.process.execute("cmd.exe /c del /F S /Q #{flagname}")
		h.close
	end
	
	def run
		# set some instance vars
		@host_info = session.sys.config.sysinfo
		@session = client
		# Make sure we meet the requirements before running the script, note no need to return
		# unless error
		return 0 if session.type != "meterpreter"
		return 0 if client.platform !~ /win32|win64/i
		# check/set vars
		rfile = datastore["REMOTEFILE"] || nil
		rdir = datastore["REMOTEDIR"] || nil
		hfile = datastore["HIDE"]
		if !datastore["HIDE"] && datastore["REMOTEFILE"] 
		  print_error("You are not hiding the file, please unset REMOTEFILE")
		  return 0
		end
		localdir = ::Dir.pwd
		flgseed = ::SecureRandom.hex(10)
		flagname = "xxx-#{flgseed}-#{@host_info['Computer']}.txt"
		@digest = ::Digest::SHA2.new(256) << ("#{flgseed}+#{rdir}")
		@flagtxt = "
		#{flagname}-#{rdir}#{rfile}

		******SECURITY FLAG******

		This file was placed here by a member of the Security team. It is not malicious and will not harm your computer.
		If you find this file please contact Security immediately using the Security distribution list.
		Please include the full location of the file, including the filename for verification purposes.

		******SECURITY FLAG******
		"
		# Make newlines work on upload to Windows system
		@flagtxt.gsub!(/(\r|\n)/, "\r\n")

		#Build flag
		secflag = ::File.new("#{flagname}", "w+")
		secflag.write @flagtxt
		secflag.close
		
		print_status("\tUploading #{localdir}/#{flagname}....")
		@session.fs.dir.chdir("#{rdir}")
		@session.fs.file.upload_file("#{flagname}","#{localdir}/#{flagname}")
		print_status("\tFlag #{flagname} uploaded!")
		
		if datastore["HIDE"]
		  print_status("Hiding flag...")
		  hide_flag(rfile,flagname)
		  print_status("...Complete")
		end

		if flagname != ""
			path = store_loot(
			"Flag",
			"text/plain",
			session,
			@flagtxt,
			"#{flagname}",
			"Flag Planted")

			print_status("Flag planted, saved in: #{path}")
		end
		
		# Delete local copy of flag
		::File.delete("#{flagname}")
	end
end
