require 'msf/core/model_xssf'

#
# This class implements a HTTP Server used for the new XSSF plugin.
#
module Msf
	module Xssf
		module XssfDatabase	

			#
			# Saves a victim in the database
			#
			def add_victim(ip, interval, ua)
				case (ua)
					when /version\/(\d+\.\d+\.\d+).*safari/;							ua_name = "SAFARI";				ua_version = $1
					when /firefox\/((:?[0-9]+\.)+[0-9]+)/;								ua_name = "Firefox";			ua_version = $1
					when /mozilla\/[0-9]\.[0-9] \(compatible; msie ([0-9]\.[0-9]+)/;	ua_name = "Internet Explorer";	ua_version = $1
					when /chrome\/((:?[0-9]+\.)+[0-9]+)/;								ua_name = "Google Chrome";		ua_version = $1
					when /opera\/((:?[0-9]+\.)+[0-9]+)/;								ua_name = "Opera";			ua_version = $1
					else 																ua_name = "Unknown";			ua_version = "Unknown"
				end
				
				case (ua)
					when /windows/;		os_name = "Windows";	arch = "ARCH_X86"
					when /linux/;		os_name = "Linux";		arch = "Unknown"
					when /iphone/;		os_name = "MAC OSX";	arch = 'armle'
					when /mac os x/;	os_name = "MAC OSX";	arch = "Unknown"
					else				os_name = "Unknown";	arch = "Unknown"
				end
				
				case (ua)
					when /windows 95/;		os_version = '95'
					when /windows 98/;		os_version = '98'
					when /windows nt 4/;	os_version = 'NT'
					when /windows nt 5.0/;	os_version = '2000'
					when /windows nt 5.1/;	os_version = 'XP'
					when /windows nt 5.2/;	os_version = '2003'
					when /windows nt 6.0/;	os_version = 'Vista'
					when /windows nt 6.1/;	os_version = '7'
					when /gentoo/;			os_version = 'Gentoo'
					when /debian/;			os_version = 'Debian'
					when /ubuntu/;			os_version = 'Ubuntu'
					else					os_version = 'Unknown'
				end
				
				case (ua)
					when /ppc/;			arch = "ARCH_PPC"
					when /x64|x86_64/;	arch = "ARCH_X86_64"
					when /i.86|wow64/;	arch = "ARCH_X86"
					else				arch = "ARCH_X86"
				end

				begin
					server = DBManager::XssfServer.find(:first, :conditions => [ "active = ?", true ])
					
					return DBManager::XssfVictim.create(
						:xssf_server_id => server.id,
						:ip => ip,
						:active => true,
						:interval => interval,
						:location => "Unknown",
						:first_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"),
						:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"),
						:tunneled => false,
						:browser_name => ua_name,
						:browser_version => ua_version,
						:os_name => os_name,
						:os_version => os_version,
						:arch => arch,
						:current_attack_url => nil,
						:cookie => "NO"
					).id
				rescue
					print_error("#{$!}")
				end
				
				return nil
			end
			
			#
			# Returns a victim with a given id
			#
			def get_victim(id)
				begin
					return  DBManager::XssfVictim.find(id)
				rescue
				end
				
				return nil
			end
			
			#
			# Register a new attack server in the database (if doesn't exist yet)
			#
			def register_server(host, port, uri)
				begin
					DBManager::XssfServer.update_all({:active => false})
					
					uri = '/' + uri if (uri[0].chr  != "/")
					uri = uri + '/' if (uri[-1].chr != "/")
		
					DBManager::XssfServer.create(:host 	=> host, :port 	=> port, :uri	=> uri,	:active	=> true) if (DBManager::XssfServer.update_all({:active => true}, ["host = ? AND port = ? AND uri = ?", host, port, uri]) == 0)
					return true
				rescue
					return false
				end
			end
			
			#
			# Returns url of active server
			#
			def active_server
				begin
					server = DBManager::XssfServer.find(:first, :conditions => [ "active = ?", true])
					return "http://#{server.host}:#{server.port}#{server.uri}"
				rescue
					print_error("#{$!}")
				end
				
				return nil
			end
			
			#
			# Updates all status of actives victims
			# If the victim does not ask for any commands in its (interval + 5) secs time, we consider that its gone
			#
			def update_active_victims
				begin
					DBManager::XssfVictim.find(:all).each do |v|
						begin
							if ((((Time.now.strftime("%Y-%m-%d %H:%M:%S").to_datetime - v.last_request.to_datetime).to_f * 100000).to_i) > (v.interval + 5).to_i) 
								v.active = false 
								DBManager::XssfWaitingAttack.delete_all([ "xssf_victim_id = ?", v.id])
							else
								v.active = true
							end
							
							v.save!
						rescue
							next
						end
					end
				rescue; end # Nothing
			end

			#
			# Display a database table
			#
			def show_table(name, klass, conditions = ["1 = 1"], delete = [])
				begin
					default_columns = klass.column_names
					
					delete.each do |i| ; default_columns.delete_if {|v| (v == i)} ; end
					
					table = Rex::Ui::Text::Table.new({'Header'  => name, 'Columns' => default_columns})
					
					klass.find(:all, :conditions => conditions).each do |o|
						columns = default_columns.map { |n| o.attributes[n] || "" }
						table << columns
					end
							
					print_line
					print_line table.to_s
				rescue
					print_error("#{$!}")
				end
			end

			#
			# Desactivate all attacks of database and desactivate victim's attacks
			#
			def clean_database
				begin
					DBManager::XssfVictim.update_all({:current_attack_url => nil, :tunneled => false})
					DBManager::XssfWaitingAttack.delete_all
				rescue; end	# Nothing
			end

			#
			# Clean a victim of attacks
			#
			def clean_victim(id)
				begin
					DBManager::XssfVictim.update(id, {:current_attack_url => nil, :tunneled => false})
				rescue;	end	# Nothing
			end
			
			#
			# Clean all victims of a given attack
			#
			def clean_victims(url = nil)
				begin
					DBManager::XssfWaitingAttack.delete_all([ "url = ?", url])
					DBManager::XssfVictim.update_all({:current_attack_url => nil}, [ "url = ?", url])
				rescue;	end	# Nothing
			end

			#
			# Creates a new attack log in the database
			#
			def create_log(victimID, result, name)
				DBManager::XssfLog.create(:xssf_victim_id => victimID, :name => name, :time => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :result => result)
				# Error => Managed at top level
			end
			
			#
			# Add an attack to a victim in waiting attacks. Add to all active victims if id is nil
			#
			def attack_victim(id, url, name)		
				begin
					if (id && (id != ''))
						if ((DBManager::XssfVictim.find(id)).active)
							DBManager::XssfWaitingAttack.create(
									:xssf_victim_id => id,
									:url => url,
									:name => name
							)
						else
							print_error("Victim '#{id}' is no longer active ! ")
						end
					else
						DBManager::XssfVictim.find(:all, :conditions => [ "active = ?", true]).each do |v|
							DBManager::XssfWaitingAttack.create(
								:xssf_victim_id => v.id,
								:url => url,
								:name => name
							)
						end
					end
					
					return true
				rescue
					return false
				end
			end
			
			#
			# Returns current attack running on a victim
			#
			def current_attack(id)
				begin
					return (DBManager::XssfVictim.find(id)).current_attack_url
				rescue
					return nil
				end
			end
			
			#
			# Adds automated attacks for a victim
			#
			def add_auto_attacks(id)
				begin
					Msf::Xssf::AUTO_ATTACKS.each do |a|
						if (obj = framework.jobs[a])
							url = "http://#{(obj.ctx[0].datastore['SRVHOST'] == '0.0.0.0' ? Rex::Socket.source_address('1.2.3.4') : obj.ctx[0].datastore['SRVHOST'])}:#{obj.ctx[0].datastore['SRVPORT']}#{obj.ctx[0].get_resource}"
							DBManager::XssfWaitingAttack.create(
								:xssf_victim_id => id,
								:url => url,
								:name => obj.name
							)
						end
					end
				rescue;	end
			end
			
			#
			# Gets and removes first attack for a victim in waiting attack list
			#
			def get_first_attack(id)
				begin
					attack = DBManager::XssfWaitingAttack.find(:first, :conditions => [ "xssf_victim_id = ?", id])
					DBManager::XssfVictim.update(id, {:current_attack_url => attack.url})
					DBManager::XssfWaitingAttack.delete(attack.id)
					return [attack.url, attack.name]
				rescue 
					return nil
				end
			end

			#
			# Specifies a victim to tunnel with
			#
			def tunnel_victim(id)
				begin
					victim = DBManager::XssfVictim.find(id, :conditions => [ "active = ?", true])
					victim.tunneled = true
					victim.save!
					
					TUNNEL.clear
					return true
				rescue
					puts $!
				end
				
				return false
			end
			
			#
			# Returns the victim currently tunneled if one
			#
			def victim_tunneled
				begin
					return DBManager::XssfVictim.find(:first, :conditions => [ "tunneled = ? AND active = ?", true, true])
				rescue
				end
				
				return nil
			end
			
			#
			# Updates a victim
			#
			def update_victim(id, location, interval = nil)
				begin
					if (interval)
						DBManager::XssfVictim.update(id, {:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :active => true, :interval => interval, :location => (CGI::unescape(location)).gsub(/\?.*/, '')})
					else
						DBManager::XssfVictim.update(id, {:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :active => true, :location => (CGI::unescape(location)).gsub(/\?.*/, '')})
					end
				rescue
					begin
						DBManager::XssfVictim.update(id, {:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :active => true})
					rescue
					end
				end
			end
			
			#
			# Sets victim cookie to YES
			#
			def victim_cookie(id)
				begin
					DBManager::XssfVictim.update(id, {:cookie => "YES"})
				rescue
				end
			end
			
			#
			# Returns the victims curently attacked
			#
			def attacked_victims
				begin
					victims = Hash.new("victims")

					DBManager::XssfWaitingAttack.find(:all, :order => "xssf_victim_id ASC").each do |v|
						victims.has_key?(v.xssf_victim_id) ? (victims[v.xssf_victim_id] = victims[v.xssf_victim_id] + 1) : (victims[v.xssf_victim_id] = 1)
					end
				rescue;	end
				
				if (not victims.empty?)
					str = "Remaining victims to attack : "
					victims.each_pair {|key, value| str << "[#{key} (#{value})] " }
					print_good(str)
				else
					print_good("Remaining victims to attack : NONE")
				end
			end

			#
			# Export attack results for a given victim id
			#
			def export_attacks(id)
				begin
					victim = DBManager::XssfVictim.find(id)
				rescue
					victim = nil
				end

				(victim) ? title = "Attack results for victim #{victim.id} (#{victim.ip})" : title = "UNKNOWN VICTIM ID"

				html = %Q{
					<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
					<html>	<head><meta http-equiv="content-type" content="text/html; charset=UTF-8">
								<title>#{title}</title>
								<style type="text/css"> hr {color: #00FF00; background-color: #00FF00; height: 1px; } </style> 
							</head>

							<body BGCOLOR=BLACK TEXT=WHITE LINK=BLUE>
								<script type="text/javascript">
									function doMenu(item) {
										obj = document.getElementById(item);
										col = document.getElementById("x" + item);

										if (obj.style.display == "none") {
												obj.style.display = "block";
												col.innerHTML = "[HIDE]";
										} else {
											obj.style.display = "none";
											col.innerHTML = "[SHOW]";
										}
									}
								</script>
								<pre>#{Xssf::XssfBanner.to_s}</pre> <pre><h2 align="right">#{title}</h2></pre> <hr><br/>
				}

				begin
					DBManager::XssfLog.find(:all, :conditions => [ "xssf_victim_id = ?", id]).each do |l|
						if (l.name == nil)
							html << %Q{
								<h3 style="color:orange"> LOG NUMBER #{l.id} (ATTACK LAUNCHED) : #{l.time} <a href="JavaScript:doMenu('#{l.id}');" style="text-decoration:none;" id=x#{l.id}>[SHOW]</a> </h3>
								<div id=#{l.id} style="margin-left:5%; display:none"> <pre>#{CGI::escapeHTML(l.result)}</pre> </div>
							}
						else
							html << %Q{
								<h3 style="color:green"> LOG NUMBER #{l.id} (#{CGI::escapeHTML(l.name)}) : #{l.time} <a href="JavaScript:doMenu('#{l.id}');" style="text-decoration:none;" id=x#{l.id}>[SHOW]</a> </h3>
								<div id=#{l.id} style="margin-left:5%; display:none"> <pre>#{CGI::escapeHTML(l.result)}</pre> </div>
							}
						end
					end
				rescue # Nothing
				end

				return html + '</body></html>'
			end
		end
	end
end