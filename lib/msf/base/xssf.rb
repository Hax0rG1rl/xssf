#
# XSSF management
#
module Msf
	module Xssf

		### CONSTANTS ###
		VICTIM_LOOP		= 'loop'			# Loads victim malicious loop code inside page (Javascript)
		VICTIM_ASK		= 'ask'
		VICTIM_ANSWER	= 'answer'
		VICTIM_TEST		= 'test.html'
		VICTIM_LOG		= 'log.html'
		VICTIM_INTERVAL	= 10				# in sec (means : victim requests for new code comming from attacker each 10 seconds)
		
		PARAM_LOCATION	= 'location'		# Information relative to parameters in request (POST/GET)
		PARAM_INTERVAL	= 'interval'
		PARAM_RESPONSE	= 'response'
		PARAM_TYPE		= 'type'			# 0 for module response, 1 for tunnel response
		PARAM_CTYPE		= 'content_type'
		PARAM_NAME		= 'name'
		PARAM_ID		= 'id'				# Rescue param for browser desactivating cookies
		
		INCLUDED_FILES = './data/xssf'
		
		# Files containing binary data can't be processed in javascript 
		PROXY_FORBIDEN = [ '.jpg', '.jpeg', '.ico', '.swf', '.gif', '.tif', '.tiff', '.mov', '.mp3', '.pdf', '.doc', '.png']
		
		AUTO_ATTACKS = []					# Automated attacks for XSSF
		
		TUNNEL = []							# Informations relative to Xssf Tunnel
		TUNNEL_LOCKED = Mutex.new			# Manages accesses to TUNNEL
    end
end

require 'msf/base/xssf/xssfproxy'
require 'msf/base/xssf/xssfdatabase'
require 'msf/base/xssf/xssfmaster'
require 'msf/base/xssf/xssfserver'
require 'msf/base/xssf/xssfbanner'