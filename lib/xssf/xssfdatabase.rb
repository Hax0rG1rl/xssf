require 'yaml'

#
# This class implements Database used for XSSF plugin.
#
# TODO: IMPLEMENT MUTEX FOR DB OBJECTS ACCESSES IF ISSUED
#
module Msf
	module Xssf
		module XssfDatabase

			#     ----------------------------                    ----------------------------
			#     |        xssf_log          |                    |      xssf_victim         |
			#     ----------------------------                    ----------------------------
			#     |  id                      |                    |  id                      |
			#     |  victim_id               |____________________|  server_id               |
			#     |  ...                     |*                  1|  ...                     |
			#     ----------------------------                    ----------------------------
			#                                                  / *            1|
			#                                               /                  |
			#                                            /                     |
			#                                         /                        |
			#                                      /                           |
			#                                   /                             *|
			#     ----------------------------  1                 ----------------------------
			#     |      xssf_server         |                    |    xssf_waiting_attack   |
			#     ----------------------------                    ----------------------------
			#     |  id                      |                    |  id                      |
			#     |  ...                     |                    |  victim_id               |
			#     |                          |                    |  ...                     |
			#     ----------------------------                    ----------------------------

			XSSF_VICTIM_DB 		= Array.new
			XSSF_VICTIM_HASH = {
				"ID" 			=> 0,
				"SERVER_ID" 		=> 1,
				"IP"			=> 2,
				"ACTIVE"		=> 3,
				"INTERVAL" 		=> 4,
				"LOCATION" 		=> 5,
				"FIRST_REQUEST" 	=> 6,
				"LAST_REQUEST" 		=> 7,
				"TUNNELED" 		=> 8,
				"BROWSER_NAME" 		=> 9,
				"BROWSER_VERSION" 	=> 10,
				"OS_NAME" 		=> 11,
				"OS_VERSION" 		=> 12,
				"ARCH" 			=> 13,
				"CURRENT_ATTACK_URL" 	=> 14,
				"COOKIE" 		=> 15}

			XSSF_LOG_DB 		= Array.new
			XSSF_LOG_HASH = {
				"ID"			=> 0,
				"VICTIM_ID"		=> 1,
				"NAME"			=> 2,
				"TIME"			=> 3,
				"RESULT"		=> 4}
				
			XSSF_SERVER_DB 		= Array.new
			XSSF_SERVER_HASH = {
				"ID"			=> 0,
				"HOST"			=> 1,
				"PORT"			=> 2,
				"URI"			=> 3,
				"ACTIVE"		=> 4}
	
			XSSF_WAITING_ATTACKS_DB	= Array.new
			XSSF_WAITING_ATTACKS_HASH = {
				"ID"			=> 0,
				"VICTIM_ID"		=> 1,
				"URL"			=> 2,
				"NAME"			=> 3}

			#
			# Returns last id from given table
			#
			def last_id(table, table_hash)
				if (table.length > 0)
					return (table[-1][table_hash["ID"]]).to_i
				else
					return 0
				end
			end

			#
			# Updates all fields within table with given value and given conditions
			#
			def update_all(table, table_hash, values = {}, conditions = {})
			        ctx = 0
				len = table.length - 1
				
				for i in 0..len
					update = true
					
					conditions.each do |key, val|
						if (table[i][table_hash[key]] != val)
							update = false
							break
						end
					end
					
					if (update)
						values.each do |field, val|
							table[i][table_hash[field]] = val
						end
						ctx = ctx + 1
					end
				end
				
				return ctx
			end

			#
			# Returns first value from table corresponding to conditions
			#
			def find(table, table_hash, conditions = {})
				len = table.length - 1
				
				for i in 0..len
					found = true
					
					conditions.each do |key, val|
						if (table[i][table_hash[key]] != val)
						 	found = false
							break
						end
					end
					
					if (found)
						return table[i]
					end
				end
				
				return nil
			end

			#
			# Returns values from table corresponding to conditions
			#
			def find_all(table, table_hash, conditions = {})
				res = []
				len = table.length - 1
				
				for i in 0..len
					found = true
					
					conditions.each do |key, val|
						if (table[i][table_hash[key]] != val)
							found = false
							break
						end
					end
					
					if (found)
						res << table[i]
					end
				end
				
				return res
			end
			
			#
			# Count all table elements matching with given condition
			#
			def count_all(table, table_hash, conditions = {})
				ctx = 0
				len = table.length - 1
				
				for i in 0..len
					found = true
					
					conditions.each do |key, val|
						if (table[i][table_hash[key]] != val)
							found = false
							break
						end
					end
					
					if (found)
						ctx = ctx + 1
					end
				end
				
				return ctx
			end
			
			#
			# Clear all data from given table
			#
			def delete_all(table)
				table.clear
			end

			#
			# Clear data from given table with given conditions
			#
			def delete(table, table_hash, conditions = {})
				len = table.length - 1

				len.downto(0) { |i|
				        del = true
				              
					conditions.each do |key, val|
						if (table[i][table_hash[key]] != val)
							del = false
							break
						end
					end
   
					if (del)
						table.delete_at(i)
					end
				}
			end
			
			#
			# Saves a victim in the database
			#
			def add_victim(ip, interval, ua)
				case (ua)
					when /version\/(\d+\.\d+[\.\d+]*).*safari/;				ua_name = "SAFARI";		ua_version = $1
					when /firefox\/((:?[0-9]+\.)+[0-9]+)/;					ua_name = "Firefox";		ua_version = $1
					when /mozilla\/[0-9]\.[0-9] \(compatible; msie ([0-9]\.[0-9]+)/;	ua_name = "Internet Explorer";	ua_version = $1
					when /chrome\/((:?[0-9]+\.)+[0-9]+)/;					ua_name = "Google Chrome";	ua_version = $1
					when /opera\/((:?[0-9]+\.)+[0-9]+)/;					ua_name = "Opera";		ua_version = $1
					else 									ua_name = "Unknown";		ua_version = "Unknown"
				end
				
				case (ua)
					when /windows/;		os_name = "Windows";	arch = "ARCH_X86"
					when /linux/;		os_name = "Linux";	arch = "Unknown"
					when /iphone/;		os_name = "MAC OSX";	arch = "armle"
					when /mac os x/;	os_name = "MAC OSX";	arch = "Unknown"
					else			os_name = "Unknown";	arch = "Unknown"
				end
				
				case (ua)
					when /windows 95/;		os_version = '95'
					when /windows 98/;		os_version = '98'
					when /windows nt 4/;		os_version = 'NT'
					when /windows nt 5.0/;		os_version = '2000'
					when /windows nt 5.1/;		os_version = 'XP'
					when /windows nt 5.2/;		os_version = '2003'
					when /windows nt 6.0/;		os_version = 'Vista'
					when /windows nt 6.1/;		os_version = '7'
					when /gentoo/;			os_version = 'Gentoo'
					when /debian/;			os_version = 'Debian'
					when /ubuntu/;			os_version = 'Ubuntu'
					when /android\s(\d+\.\d+)/;	os_version = 'Android (' + $1 + ')'
					else				os_version = 'Unknown'
				end
				
				case (ua)
					when /ppc/;		arch = "ARCH_PPC"
					when /x64|x86_64/;	arch = "ARCH_X86_64"
					when /i.86|wow64/;	arch = "ARCH_X86"
					else			arch = "ARCH_X86"
				end

				begin
					server = find(XSSF_SERVER_DB, XSSF_SERVER_HASH, {"ACTIVE" => true})
					last_id = last_id(XSSF_VICTIM_DB, XSSF_VICTIM_HASH)
					
					XSSF_VICTIM_DB << [last_id + 1,
					                   server[XSSF_SERVER_HASH["ID"]].to_i,
					                   ip,
					                   true,
					                   (interval <= 0) ? 1 : ((interval >= 600) ? 600 : interval),
					                   "Unknown",
					                   Time.now.strftime("%Y-%m-%d %H:%M:%S"),
					                   Time.now.strftime("%Y-%m-%d %H:%M:%S"),
					                   false,
					                   ua_name,
					                   ua_version.slice!(0..15),
					                   os_name,
					                   os_version.slice!(0..15),
					                   arch,
					                   nil,
					                   "NO"]
					
					return last_id + 1
				rescue
					print_error("Error 4: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Returns a victim with a given id
			#
			def get_victim(id)
				begin
					return find(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ID" => id.to_i})
				rescue
					print_error("Error 5: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Register a new attack server in the database (if doesn't exist yet)
			#
			def register_server(host, port, uri)
				begin
					update_all(XSSF_SERVER_DB, XSSF_SERVER_HASH, {"ACTIVE" => false})
					if (update_all(XSSF_SERVER_DB, XSSF_SERVER_HASH, {"ACTIVE" => true}, {"HOST" => host, "PORT" => port, "URI" => uri}) == 0)
						XSSF_SERVER_DB << [last_id(XSSF_SERVER_DB, XSSF_SERVER_HASH) + 1, host, port.to_i, uri, true]
					end
					
					return true
				rescue
					print_error("Error 6: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return false
				end
			end
			
			#
			# Returns url of active server
			#
			def active_server
				begin
					server = find(XSSF_SERVER_DB, XSSF_SERVER_HASH, {"ACTIVE" => true})
					return [server[XSSF_SERVER_HASH["HOST"]], server[XSSF_SERVER_HASH["PORT"]], server[XSSF_SERVER_HASH["URI"]]]
				rescue
					print_error("Error 7: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Updates all status of actives victims
			# If the victim does not ask for any commands in its (interval + 5) secs time, we consider that its gone
			#
			def update_active_victims
				begin
				        find_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH).each do |v|
						begin
							if ((((Time.now.strftime("%Y-%m-%d %H:%M:%S").to_datetime - v[XSSF_VICTIM_HASH["LAST_REQUEST"]].to_datetime).to_f * 100000).to_i) > (v[XSSF_VICTIM_HASH["INTERVAL"]] + 5).to_i)
								v[XSSF_VICTIM_HASH["ACTIVE"]] = false
							else
								v[XSSF_VICTIM_HASH["ACTIVE"]] = true
							end
						rescue
							next
						end
					end
				rescue
					print_error("Error 8: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Display a database table
			#
			def show_table(name, table, table_hash, conditions = {}, delete = [])
			  	begin
					default_columns = []
					table_hash.each do |key, val|
						default_columns << key
					end
					
					delete.each do |i| ; default_columns.delete_if {|v| (v == i)} ; end
					
					tbl = Rex::Ui::Text::Table.new({'Header'  => name, 'Columns' => default_columns})
					
					len1 = table.length - 1
					len2 = default_columns.length - 1
				
					find_all(table, table_hash, conditions).each do |victim|
						line = []
						for i in 0..len2
							line << victim[table_hash[default_columns[i]]].to_s
						end
						tbl << line
					end
							
					print_line
					print_line tbl.to_s
				rescue
					print_error("Error 9: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Desactivate all attacks of database and desactivate victim's attacks
			#
			def clean_database
				begin
					update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"CURRENT_ATTACK_URL" => nil, "TUNNELED" => false})
					delete_all(XSSF_WAITING_ATTACKS_DB) 
				rescue
					print_error("Error 10: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Clean a victim of attacks
			#
			def clean_victim(id)
				begin
					if (id && (id != ''))
						update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"CURRENT_ATTACK_URL" => nil, "TUNNELED" => false}, {"ID" => id.to_i})
						delete(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH, {"VICTIM_ID" => id.to_i}) 
					else
						clean_database
					end
					
				rescue
					print_error("Error 11: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Creates a new attack log in the database
			#
			def create_log(victimID, result, name)
				XSSF_LOG_DB << [last_id(XSSF_LOG_DB, XSSF_LOG_HASH) + 1,
				                victimID.to_i,
					        name,
					        Time.now.strftime("%Y-%m-%d %H:%M:%S"),
					        result]
			end
			
			#
			# Add an attack to a victim in waiting attacks. Add to all active victims if id is nil
			#
			def attack_victim(id, url, name)		
				begin
					if (id && (id != ''))
						if (find(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ID" => id.to_i})[XSSF_VICTIM_HASH["ACTIVE"]])
							XSSF_WAITING_ATTACKS_DB << [last_id(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH) + 1,
							                            id.to_i,
							                            url,
							                            name]
						else
							print_error("Victim '#{id}' is no longer active ! ")
						end
					else
						find_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ACTIVE" => true}).each do |v|
							  XSSF_WAITING_ATTACKS_DB << [last_id(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH) + 1,
							                              v[XSSF_VICTIM_HASH["ID"]].to_i,
							                              url,
							                              name]
						end
					end
					return true
				rescue
					(id && (id != '')) ? print_error("Error adding attack to victim #{id} - Check if victim exists") : print_error("Error adding attack to some victims")
					return false
				end
			end
			
			#
			# Returns current attack running on a victim
			#
			def current_attack(id)
				begin
					id ? v = (find(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ID" => id.to_i})) : v = nil
					
					if (v)
						return v[XSSF_VICTIM_HASH["CURRENT_ATTACK_URL"]]
					else
						return nil
					end
				rescue
					print_error("Error 12: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end
			
			#
			# Adds automated attacks for a victim
			#
			def add_auto_attacks(id)
				begin
					AUTO_ATTACKS.each do |a|
						if (obj = framework.jobs[a])
							url = "http://#{(obj.ctx[0].datastore['SRVHOST'] == '0.0.0.0' ? Rex::Socket.source_address('1.2.3.4') : obj.ctx[0].datastore['SRVHOST'])}:#{obj.ctx[0].datastore['SRVPORT']}#{obj.ctx[0].get_resource}"
							XSSF_WAITING_ATTACKS_DB << [last_id(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH) + 1,
							                            id.to_i,
							                            url,
							                            obj.name]
						end
					end
				rescue
					print_error("Error 13: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
			
			#
			# Gets and removes first attack for a victim in waiting attack list
			#
			def get_first_attack(id)
				begin
					attack = find(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH, {"VICTIM_ID" => id.to_i})

					if (attack)
						update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"CURRENT_ATTACK_URL" => attack[XSSF_WAITING_ATTACKS_HASH["URL"]]}, {"ID" => id.to_i})
						delete(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH, {"ID" => attack[XSSF_WAITING_ATTACKS_HASH["ID"]]})
						return [attack[XSSF_WAITING_ATTACKS_HASH["URL"]], attack[XSSF_WAITING_ATTACKS_HASH["NAME"]]]
					else
						return nil
					end
				rescue
					print_error("Error 14: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end

			#
			# Specifies a victim to tunnel with
			#
			def tunnel_victim(id)
				begin
					delete(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH, {"VICTIM_ID" => id.to_i})
					ctx = update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"TUNNELED" => true}, {"ID" => id.to_i, "ACTIVE" => true})

					TUNNEL.clear
					
					if (ctx == 0)
						return nil
					else
						return victim_tunneled
					end
				rescue
					print_error("Error 15: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Returns the victim currently tunneled if one
			#
			def victim_tunneled
				begin
					return find(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"TUNNELED" => true, "ACTIVE" => true})
				rescue
					print_error("Error 16: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Updates a victim
			#
			def update_victim(id, location, interval = nil, cookie = "NO")
				begin
					uri = URI.parse(URI.escape(CGI::unescape(location)))
					location = uri.scheme.to_s + "://" + uri.host.to_s + ":" + uri.port.to_s
				rescue
					location = "Unknown"
				end
				
				location = "Unknown" if (location == "://:")
				
				begin
					if (interval)
						update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"LAST_REQUEST" => Time.now.strftime("%Y-%m-%d %H:%M:%S"), "ACTIVE" => true, "INTERVAL" => interval, "LOCATION" => location, "COOKIE" => cookie}, {"ID" => id.to_i})
					else
					  	update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"LAST_REQUEST" => Time.now.strftime("%Y-%m-%d %H:%M:%S"), "ACTIVE" => true, "LOCATION" => location, "COOKIE" => cookie}, {"ID" => id.to_i})
					end
				rescue
					begin
						update_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"LAST_REQUEST" => Time.now.strftime("%Y-%m-%d %H:%M:%S"), "ACTIVE" => true, "COOKIE" => cookie}, {"ID" => id.to_i})
					rescue
						print_error("Error 17: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				end
			end
			
			
			#
			# Returns the victims curently attacked
			#
			def attacked_victims
				begin
					victims = Hash.new("victims")

					find_all(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH).each do |wa|
						victims.has_key?([XSSF_WAITING_ATTACKS_HASH["VICTIM_ID"]]) ? (victims[[XSSF_WAITING_ATTACKS_HASH["VICTIM_ID"]]] = victims[[XSSF_WAITING_ATTACKS_HASH["VICTIM_ID"]]] + 1) : (victims[[XSSF_WAITING_ATTACKS_HASH["VICTIM_ID"]]] = 1)
					end
				rescue
					print_error("Error 18: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				if (not victims.empty?)
					str = "Remaining victims to attack: "
					victims.each_pair {|key, value| str << "[#{key} (#{value})] " }
					print_good(str) if not (XSSF_MODE[0] =~ /^Quiet$/i)
				else
					print_good("Remaining victims to attack: NONE") if not (XSSF_MODE[0] =~ /^Quiet$/i)
				end
			end

			
			#
			# Count waiting attacks for given ID
			#
			def count_waiting_attacks(id)
				begin
					return count_all(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH, {"VICTIM_ID" => id.to_i})
				rescue
					print_error("Error 19: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return 0
				end
			end
			
			
			#
			# Generates XSSF banner page
			#
			def get_html_banner()
				html = %Q{
					<html><body bgcolor=black style="color:cyan; font-family: monospace">
						<pre>#{Xssf::XssfBanner::Logos[2]}</pre><h3 style="position:absolute; right:1%; top:75%" align="right"><u>msf ></u> _</h3>
						<table width="300" height="35" style="border: 1px solid green; position:absolute; left:450px; top:30%">
							<tr align=center>
								<td width="33%" onMouseover="this.bgColor='green'" onMouseout="this.bgColor='black'"
								onClick="parent.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=main';" style="cursor:pointer; border: 1px solid green;">LOGS</td>
								<td width="33%" onMouseover="this.bgColor='green'" onMouseout="this.bgColor='black'"
								onClick="parent.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=stats';" style="cursor:pointer; border: 1px solid green;">STATS</td>
								<td width="33%" onMouseover="this.bgColor='green'" onMouseout="this.bgColor='black'"
								onClick="parent.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=help';" style="cursor:pointer; border: 1px solid green;">HELP</td>
							</tr>
						</table>
					</body></html>
				}
				return html
			end
			
			
			#
			# Generate victims list page
			#
			def get_html_victims()
				html = %Q{
					<html><body bgcolor="#000000">
						<script type="text/javascript">
							var cache = {};
							
							function getElementsById(id){
								if(!cache[id]) {
									var nodes = [];	var tmpNode = document.getElementById(id);
									while(tmpNode) { nodes.push(tmpNode); tmpNode.id = ""; tmpNode = document.getElementById(id); }
									cache[id] = nodes;
								}
								return cache[id];
							}

							function doMenu(item) {
								if (getElementsById(item)[0].style.display == "none") {
									for (var i = 0; i < getElementsById(item).length; i++)
										getElementsById(item)[i].style.display = "";
									document.getElementById(item + "x").innerHTML = "[-]";
								} else {
									for (var i = 0; i < getElementsById(item).length; i++)
										getElementsById(item)[i].style.display = "none";
									document.getElementById(item + "x").innerHTML = "[+]";
								}
							}
						</script>
						
						<table  cellpadding=0 cellspacing=0 border=0 width=100% style="font-family: monospace">
				}
				
				begin
					find_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH).each do |v|
						begin
							secs = (Time.parse((v[XSSF_VICTIM_HASH["LAST_REQUEST"]]).to_s) - Time.parse((v[XSSF_VICTIM_HASH["FIRST_REQUEST"]]).to_s)).to_i;
							
							html << %Q{
								<tr style="color:#{v[XSSF_VICTIM_HASH["ACTIVE"]] ? "green" : "red"}; font-family: monospace" align=left>
									<td width=10%><span id="#{v[XSSF_VICTIM_HASH["ID"]]}x" onClick="doMenu('#{v[XSSF_VICTIM_HASH["ID"]]}')" style="cursor:pointer">[+]</span></td>
									<td width=35%><span onClick="parent.fr2.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=logs&#{PARAM_GUI_VICTIMID}=#{v[XSSF_VICTIM_HASH["ID"]]}'; parent.fr3.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack'" style="cursor:pointer"><b>Victim #{v[XSSF_VICTIM_HASH["ID"]]}</b></span></td>
									<td width=35%><span onClick="parent.fr2.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=logs&#{PARAM_GUI_VICTIMID}=#{v[XSSF_VICTIM_HASH["ID"]]}'; parent.fr3.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack'" style="cursor:pointer"><b>#{v[XSSF_VICTIM_HASH["IP"]]}</b></span></td>
							}
							
							case v[XSSF_VICTIM_HASH["OS_NAME"]]
								when /Windows/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}win.png" alt="Windows" /></td>}
								when /Linux/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}lin.png" alt="Linux" /></td>}
								when /MAX OSX/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}osx.png" alt="MAX OSX" /></td>}
								else
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}unknown.png" alt="Unknown" /></td>}
							end
							
							case v[XSSF_VICTIM_HASH["BROWSER_NAME"]]
								when /SAFARI/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}safari.png" alt="SAFARI" /></td>}
								when /Firefox/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}ff.png" alt="Firefox" /></td>}
								when /Internet Explorer/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}ie.png" alt="Internet Explorer" /></td>}
								when /Google Chrome/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}chrome.png" alt="Chrome" /></td>}
								when /Opera/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}opera.png" alt="Opera" /></td>}
								else
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}unknown.png" alt="Unknown" /></td>}
							end
					
							html << %Q{
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Active ?</div></td>			<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["ACTIVE"]] ? "TRUE" : "FALSE"}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">IP Address</div></td>			<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["IP"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">OS Name</div></td>			<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["OS_NAME"]]}</td>
								</tr> <tr style="display:none;" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">OS Version</div></td>			<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["OS_VERSION"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Architecture</div></td>		<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["ARCH"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Browser name</div></td>		<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["BROWSER_NAME"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Browser version</div></td>		<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["BROWSER_VERSION"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Location</div></td>			<td COLSPAN=3 style="color:purple;"><span onclick="window.open('#{v[XSSF_VICTIM_HASH["LOCATION"]]}')" style="cursor:pointer"><u>Go!</u></span></td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">XSSF cookie ?</div></td>		<td COLSPAN=3 style="color:purple;">#{(v[XSSF_VICTIM_HASH["COOKIE"]] == "YES") ? "TRUE" : "FALSE"}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">First request</div></td>		<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["FIRST_REQUEST"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Last Request</div></td>		<td COLSPAN=3 style="color:purple;">#{v[XSSF_VICTIM_HASH["LAST_REQUEST"]]}</td>
								</tr> <tr style="display:none" id="#{v[XSSF_VICTIM_HASH["ID"]]}" align=center>
									<td COLSPAN=2><div style="color:white">Connection time</div></td>		<td COLSPAN=3 style="color:purple;">#{secs/3600}hr #{secs/60 % 60}min #{secs % 60}sec</td>
								</tr>
							}
						rescue
							next
						end
					end
				rescue
					print_error("Error 20: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return html + "</table></body><html>"
			end

			
			#
			# Exports logs for a victim with a given id
			#
			def get_html_logs(id)
				html = "<html><body bgcolor=black style='font-family:monospace'>"
				
				if (id && (id != 0))
					html << %Q{
						<script>
							var cache = {};
							
							function getElementsById(id){
								if(!cache[id]) {
									var nodes = [];	var tmpNode = document.getElementById(id);
									while(tmpNode) { nodes.push(tmpNode); tmpNode.id = ""; tmpNode = document.getElementById(id); }
									cache[id] = nodes;
								}
								return cache[id];
							}
							
							function displayPage(selectid) {
								var disp0 = "block"; var disp1 = "block";
								
								switch (selectid) {
									case 1: disp1 = "none";	break;
									case 2:	disp0 = "none";	break;
									default: break;	}

								for (var i = 0; i < getElementsById("0").length; i++)	getElementsById("0")[i].style.display = disp0;
								for (var i = 0; i < getElementsById("1").length; i++)	getElementsById("1")[i].style.display = disp1;
							}
						</script>
						
						<center>
							<h3 style="color:cyan"> Victim #{id} attacks </h3>
							<table cellpadding=0 cellspacing=0 border=0 width=70% align=center style="font-family: monospace; color:cyan"><tr>
									<td><input type="radio" name="sel" value="0" onclick="displayPage(0);"> 		All		</td>
									<td><input type="radio" name="sel" value="1" onclick="displayPage(1);"> 		Launched	</td>
									<td><input type="radio" name="sel" value="2" onclick="displayPage(2);" checked> 	Results		</td>
							</tr></table>
						</center>
					}
					
					begin
						find_all(XSSF_LOG_DB, XSSF_LOG_HASH, {"VICTIM_ID" => id.to_i}).each do |l|
							if (l[XSSF_LOG_HASH["NAME"]] == nil)
								html << %Q{ <div id="0" style="color:orange; display:none"><h4> [LOG #{l[XSSF_LOG_HASH["ID"]]}]: #{URI.unescape(l[XSSF_LOG_HASH["RESULT"]]).gsub(/[<>]/, '<' => '&lt;', '>' => '&gt;')} (#{l[XSSF_LOG_HASH["TIME"]]}) </h4></div>	}
							else
								html << %Q{ <span id="1" onClick="parent.fr3.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack&#{PARAM_GUI_LOGID}=#{l[XSSF_LOG_HASH["ID"]]}'" style="cursor:pointer; color:green"><h4> [LOG #{l[XSSF_LOG_HASH["ID"]]}] : #{CGI::escapeHTML(l[XSSF_LOG_HASH["NAME"]])} (#{l[XSSF_LOG_HASH["TIME"]]}) </h4></span> }
							end
						end
					rescue
						print_error("Error 21: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				end
				
				return html + "</body></html>"
			end

			
			#
			# Exports log page with a given log id
			#
			def get_html_attack(logid)
				html = "<html><body bgcolor=black style='font-family:monospace'>"
				
				if (logid && (logid != 0))
					begin
						if (log = find(XSSF_LOG_DB, XSSF_LOG_HASH, {"ID" => logid}))
							html << %Q{
								<center>
									<h3 style="color:cyan"> Attack log #{logid} </h3>
									<form method="GET" action="#{VICTIM_GUI}" >
										<label for="ext" style="color:cyan">Export as...</label>
										<input type=text id="ext" name=#{PARAM_GUI_EXTENTION}  value="Extension" onclick="this.value = '';" >
										<input type=submit value="Download!" >
										<input type="hidden" name="#{PARAM_GUI_PAGE}" value="attack">
										<input type="hidden" name="#{PARAM_GUI_LOGID}" value="#{logid}">
										<input type="hidden" name="#{PARAM_GUI_ACTION}" value="export">
									</form>
								</center>
								<br /><h3 style="color:cyan"> Received result: </h3><div style="color:white">#{(File.open(INCLUDED_FILES + XSSF_LOG_FILES + log[XSSF_LOG_HASH["RESULT"]], "rb") {|io| io.read }).gsub(/[<>]/, '<' => '&lt;', '>' => '&gt;')}</div>
							}
						end
					rescue
						print_error("Error 22: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				end
				
				return html + "</body></html>"
			end	

			#
			# Returns statistics about atacked victims (wether they are always actives or not), in real time
			#
			def get_html_stats()
				html = %Q{
					<html><head>
						<script src="#{XSSF_GUI_FILES}swfobject.js" type="text/javascript"></script>
						<script type="text/javascript">
							function createXHR() {
								if (window.XMLHttpRequest) return new XMLHttpRequest();
			 
								if (window.ActiveXObject) {
									var names = ["Msxml2.XMLHTTP.6.0", "Msxml2.XMLHTTP.3.0", "Msxml2.XMLHTTP", "Microsoft.XMLHTTP"];
									for(var i in names) {
										try{ return new ActiveXObject(names[i]); }
										catch(e){}
									}
								}
							}
				}
				
				for i in (1..5)
					html << %Q{ 
						swfobject.embedSWF("#{XSSF_GUI_FILES}ofc.swf", "gr#{i}", "100%", "275", "9.0.0", "expressInstall.swf", {"data-file":"#{VICTIM_GUI}?#{PARAM_GUI_JSON}%3Dgr#{i}%26#{PARAM_GUI_PAGE}%3Dstat"});
				
						setInterval(update#{i}, 3000);
						
						function update#{i}() {
							chart_#{i} = document.getElementById("gr#{i}");

							xhr#{i} = createXHR();
							xhr#{i}.open("GET", '#{VICTIM_GUI}?#{PARAM_GUI_JSON}=gr#{i}&#{PARAM_GUI_PAGE}=stat&time=' + escape(new Date().getTime()), true);
							xhr#{i}.send(null);
									
							xhr#{i}.onreadystatechange=function() {	if (xhr#{i}.readyState == 4) { chart_#{i}.load(xhr#{i}.responseText); } }
						}
					}
				end

				html << %Q{					
					</script>
					</head><body bgcolor=black style='font-family:monospace'>
						<table width=100% height=95% cellpadding=0 cellspacing=0 cellmargin=0 BORDER>
							<tr>
								<td><div id="gr1"></div></td><td><div id="gr3"></div></td><td rowspan=2 width=40%><div id="gr5"></div></td>
							</tr>
							<tr>
								<td><div id="gr2"></div></td><td><div id="gr4"></div></td>
							</tr>
						</table>
						<center><div style="color:white">Charts provided by <a href="javascript: top.location='http://teethgrinder.co.uk/open-flash-chart/'">"Open Flash Chart"</a></div></center>
					</body></html>
				}
				
				return html
			end
			
			
			#
			# Builds graphs data in real time for statistic page
			#
			def build_json(json)
				begin; code = ""; 	table = Hash.new; 	str = "";	victims = find_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH); rescue; end
				
				colours = %Q{ 	"0x336699", "0x88AACC", "0x999933", "0x666699", "0xCC9933", "0x006666", "0x3399FF", "0x993300", "0xAAAA77", "0x666666", "0xFFCC66", "0x6699CC",
						"0x663366", "0x9999CC", "0xAAAAAA", "0x669999", "0xBBBB55", "0xCC6600", "0x9999FF", "0x0066CC", "0x99CCCC", "0x999999", "0xFFCC00", "0x009999",
						"0x99CC33", "0xFF9900", "0x999966", "0x66CCCC", "0x339966", "0xCCCC33"	}
				case json
					when /^gr1$/			# Active / Non active victims
						total = 0;		active = 0;
						
						begin
							total = count_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH);	active = count_all(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ACTIVE" => true})
						rescue
							total = 0;	active = 0
						end
				
						code = %Q{ { 	"elements": [ { "type": "pie", "start-angle": 50, "animate": [ { "type": "fade" },{ "type": "bounce", "distance": 20 } ],
								"on-show": false, "gradient-fill": true, "colours" : ["#00FF00", "#FF0000"], "tip": "#label#\n#val# of #total# (#percent#)", 
								"no-labels": true, "values": [ { "value": #{active}, "label": "Connected", "label-colour": "#00FF00" }, 
								{ "value": #{total - active}, "label": "Disconnected", "label-colour": "#FF0000" }] } ], "bg_colour" : "#000000", 
								"title": { "text": "Active victims",  "style": "color: #00EEEE; font-size: 20px" } }
								}
						
					when /^gr2$/			# Victims location
						victims.each do |v|;	begin;	table[v[XSSF_VICTIM_HASH["LOCATION"]]] ? table[v[XSSF_VICTIM_HASH["LOCATION"]]] += 1 : table[v[XSSF_VICTIM_HASH["LOCATION"]]] = 1;	rescue;	next;	end;	end

						table.each do |key, value|;	str << %Q{ {"value" : #{value.to_i}, "label": "#{key.to_s}", "on-click": "#{key.to_s}" },};	end
						
						code = %Q{	{ 	"elements": [ { "type": "pie", "start-angle": 50, "on-show": false, "animate": [ { "type": "fade" }, { "type": "bounce", "distance": 20 } ],
									"colours" : [#{colours}], "gradient-fill": true, "tip": "#label#\n#val# of #total# (#percent#)", "no-labels": true, 
									"values": [ #{str[0..-2].to_s} ]}], "bg_colour" : "#000000", "title": { "text": "XSSed domains",  "style": "color: #00EEEE; font-size: 20px" } }
								}

					when /^gr3$/			# Victim OS statistics
						victims.each do |v|
							begin
								table[v[XSSF_VICTIM_HASH["OS_NAME"]]] = Hash.new if not table[v[XSSF_VICTIM_HASH["OS_NAME"]]]
								table[v[XSSF_VICTIM_HASH["OS_NAME"]]][v[XSSF_VICTIM_HASH["OS_VERSION"]]] ? table[v[XSSF_VICTIM_HASH["OS_NAME"]]][v[XSSF_VICTIM_HASH["OS_VERSION"]]] += 1 : table[v[XSSF_VICTIM_HASH["OS_NAME"]]][v[XSSF_VICTIM_HASH["OS_VERSION"]]] = 1
							rescue;	next; end
						end


						table.each do |key, value|;	value.each do |k, v|;	str << %Q{ {"value" : #{v.to_i}, "label": "#{key.to_s} [#{k.to_s}]" },};	end;	end
						
						code = %Q{ { 	"elements": [ { "type": "pie", "start-angle": 50, "on-show": false, "animate": [ { "type": "fade" }, { "type": "bounce", "distance": 20 } ],
								"colours" : [#{colours}],"gradient-fill": true, "tip": "#label#\n#val# of #total# (#percent#)", "no-labels": true, 
								"values": [ #{str[0..-2].to_s} ]}], "bg_colour" : "#000000", "title": { "text": "Operating Systems",  "style": "color: #00EEEE; font-size: 20px" } }
								}
						
					when /^gr4$/				# Victim browsers statistics
						victims.each do |v|
							begin
								table[v[XSSF_VICTIM_HASH["BROWSER_NAME"]]] = Hash.new if not table[v[XSSF_VICTIM_HASH["BROWSER_NAME"]]]
								table[v[XSSF_VICTIM_HASH["BROWSER_NAME"]]][v[XSSF_VICTIM_HASH["BROWSER_VERSION"]]] ? table[v[XSSF_VICTIM_HASH["BROWSER_NAME"]]][v[XSSF_VICTIM_HASH["BROWSER_VERSION"]]] += 1 : table[v[XSSF_VICTIM_HASH["BROWSER_NAME"]]][v[XSSF_VICTIM_HASH["BROWSER_VERSION"]]] = 1
							rescue;	next; end
						end

						table.each do |key, value|;	value.each do |k, v|;	str << %Q{ {"value" : #{v.to_i}, "label": "#{key.to_s} [#{k.to_s}]" },};	end;	end
						
						code = %Q{ { 	"elements": [ { "type": "pie", "start-angle": 50, "on-show": false,	"animate": [ { "type": "fade" }, { "type": "bounce", "distance": 20 } ],
								"colours" : [#{colours}], "gradient-fill": true, "tip": "#label#\n#val# of #total# (#percent#)", "no-labels": true, 
								"values": [ #{str[0..-2].to_s} ]}], "bg_colour" : "#000000", "title": { "text": "XSSed browsers",  "style": "color: #00EEEE; font-size: 20px" } }
								}
						
					else						# Victim number evolution for the last 10 days
						t = Time.now; 	max = 0;	
						9.downto(0) do |i|;	table[t - (i * 86400)] = 0;	end
							
						victims.each do |v|
							table.each_key do |k|
								time = Time.parse(v[XSSF_VICTIM_HASH["FIRST_REQUEST"]])
								table[k] += 1 if ((time.year == k.year) and (time.yday == k.yday))
								max = table[k] if (table[k] > max)
							end
						end

						table.each do |key, value|;	str << %Q{ {"x" : #{Time.parse(key.to_s).to_i}, "y": #{value} },};	end
						
						code = %Q{ { "elements": [ { "type": "scatter_line", "colour": "#00FF00", "width": 3, "values": [ #{str[0..-2].to_s} ], 
							"dot-style": { "type": "hollow-dot", "dot-size": 3, "halo-size": 2 } } ], 
							"title": { "text": "Victims number evolution",  "style": "color: #00EEEE; font-size: 20px" }, 
							"x_axis": {"colour": "#00EEEE","grid-colour": "#555555","min": #{(t - (9 * 86400)).to_i}, "max": #{t.to_i}, "steps": 86400, "labels": { 
								"text": "#date:jS, M Y#", "steps": 86400, "visible-steps": 1, "rotate": 270, "colour" : "#FFFFFF" } }, 
							"y_axis": {"colour": "#00EEEE", "grid-colour": "#555555","min": 0, "max": #{max + 5}, "steps": 2, "labels": {"colour" : "#FFFFFF"} },"bg_colour":"#000000" }
						}
				end
				
				return code
			end
			
			
			# 
			# Returns browser name and version of victim with given ID
			#
			def browser_info(id)
				begin
					v = find(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ID" => id.to_i})
					return [v[XSSF_VICTIM_HASH["BROWSER_NAME"]].to_s, v[XSSF_VICTIM_HASH["BROWSER_VERSION"]].to_f, v[XSSF_VICTIM_HASH["OS_VERSION"]].to_s]
				rescue
					print_error("Error 23: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return ["Unknown", "0"]
			end
			
			
			#
			# Returns content of given log id
			#
			def get_log_content(logid)
				begin
					return File.open(INCLUDED_FILES + XSSF_LOG_FILES + find(XSSF_LOG_DB, XSSF_LOG_HASH, {"ID" => logid.to_i})[XSSF_LOG_HASH["RESULT"]], "rb") {|io| io.read }
				rescue
					print_error("Error 24: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end
			
			
			#
			# Processes all victims inside string with given function
			#
			# Function "attack_victim" => ID's [NONE / ALL (Default) / 1, 2, 6-12]
			# Function "remove_victim"  => ID's [ALL (Default) / 1, 2, 6-12]
			# Function "clean_victim"  => ID's [ALL (Default) / 1, 2, 6-12]
			#
			def process_victims_string(ids, function, url, name)
				if ((ids =~ /^ALL$/) or (ids =~ /^$/))
					case function
						when "attack_victim"
							attack_victim(nil, url, name)
						when "remove_victim"
							remove_victim(nil)
						else #clean_victim
							clean_victim(nil)
					end
				else
					(ids.split(',')).each do |v|
						if (v =~ /^(\d+)-(\d+)$/) 
							($1..$2).each do |id|
								case function
									when "attack_victim"
										attack_victim(id.to_i, url, name)
									when "remove_victim"
										remove_victim(id.to_i)
									else #clean_victim
										clean_victim(id.to_i)
								end
							end
						else
							if (v =~ /^(\d+)$/)
								case function
									when "attack_victim"
										attack_victim($1.to_i, url, name)
									when "remove_victim"
										remove_victim($1.to_i)
									else #clean_victim
										clean_victim($1.to_i)
								end
							else
								print_error("Wrong victim ID or range '#{v}'")
							end
						end
					end
				end
			end
			
			
			#
			# Clear victims in database (alls if id = nil)
			#
			def remove_victim(id)
				begin
					if (id && (id != ''))
						delete(XSSF_WAITING_ATTACKS_DB, XSSF_WAITING_ATTACKS_HASH, {"VICTIM_ID" => id.to_i})
						delete(XSSF_LOG_DB, XSSF_LOG_HASH, {"VICTIM_ID" => id.to_i})
						delete(XSSF_VICTIM_DB, XSSF_VICTIM_HASH, {"ID" => id.to_i})
					else
						delete_all(XSSF_WAITING_ATTACKS_DB)
						delete_all(XSSF_LOG_DB)
						delete_all(XSSF_VICTIM_DB)
					end
				rescue
					print_error("Error 25: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
			
			#
			# Saves current database state into output file
			#
			def save_db(file)
				begin
					File.open(file,'w') do|f|
						f.puts XSSF_SERVER_DB.to_yaml
						f.puts XSSF_VICTIM_DB.to_yaml
						f.puts XSSF_WAITING_ATTACKS_DB.to_yaml
						f.puts XSSF_LOG_DB.to_yaml
					end
				rescue
					print_error("Error 26: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
			
			#
			# Recovers database state from input file
			#
			def restore_db(file)
				begin
					if File.exists?(file)
						delete_all(XSSF_WAITING_ATTACKS_DB)
						delete_all(XSSF_LOG_DB)
						delete_all(XSSF_VICTIM_DB)
						delete_all(XSSF_SERVER_DB)
						
						ctx = 0
						
						YAML.load_documents(File.read(file)) {|a|
							XSSF_SERVER_DB.concat(a) if (ctx == 0)
							XSSF_VICTIM_DB.concat(a) if (ctx == 1)
							XSSF_WAITING_ATTACKS_DB.concat(a) if (ctx == 2)
							XSSF_LOG_DB.concat(a) if (ctx == 3)
						                                     
							ctx = ctx + 1
						}
					else
						raise "File not found..."
					end
				rescue
					print_error("Error 26: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
		end
	end
end