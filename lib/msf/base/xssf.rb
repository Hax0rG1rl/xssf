#
# XSSF management
#
module Msf
	module Xssf

		XSSF_VERSION	= '2.1'
		
		### CONSTANTS ###
		SERVER_PORT		= 8888
		SERVER_URI 		= '/'
		
		VICTIM_LOOP		= 'loop'			# Loads victim malicious loop code inside page (Javascript)
		VICTIM_ASK		= 'ask'
		VICTIM_ANSWER	= 'answer'
		VICTIM_SAFARI	= 'cookie_safari'	# Safari needs a first special POST insade Iframe to set Cross-Domain Cookie
		VICTIM_TEST		= 'test.html'
		VICTIM_GUI		= 'gui.html'
		VICTIM_INTERVAL	= 10				# in sec (victim requests for new code comming from attacker each 10 seconds)
		
		PARAM_LOCATION	= 'location'		# Information relative to parameters in request (POST/GET)
		PARAM_INTERVAL	= 'interval'
		PARAM_RESPONSE	= 'response'
		PARAM_HEADERS	= 'headers'
		PARAM_NAME		= 'name'
		PARAM_RESPID	= 'responseid'		# Useful for XSSF Tunnel
		PARAM_ID		= 'id'				# Rescue param for browser desactivating cookies
		
		PARAM_GUI_PAGE		= 'guipage'			# main | banner | victims | logs | attack | stats | stat | help | helpmenu | helpdetails
		PARAM_GUI_ACTION	= 'guiaction'		# view | (export [if log_page=attack])
		PARAM_GUI_JSON		= 'guijson'			# if guipage=stat
		PARAM_GUI_VICTIMID	= 'guivictimid'
		PARAM_GUI_LOGID		= 'guilogid'
		PARAM_GUI_EXTENTION	= 'guiextention'	# Extention of file to export
		
		XSSF_PUBLIC		= [false]			# Defines if XSSF GUI pages or Tunnel are accessible from internet (Default is only by local machine running MSF)
		XSSF_DEBUG_MODE	= [false]			# Defines if XSSF debug mode is activated (default does not display exceptions)
		XSSF_QUIET_MODE	= [false]			# Defines if XSSF quiet mode if activated. If activated, status messages about modules execution and tunnel won't be displayed
		
		INCLUDED_FILES = Config.data_directory + '/xssf'
		XSSF_RRC_FILES = '/resources/'
		XSSF_GUI_FILES = '/gui/'
		XSSF_LOG_FILES = '/logs/'
		
		AUTO_ATTACKS = []					# Automated attacks for XSSF (cleared when closing XSSF)
		
		TUNNEL = Hash.new					# Information relative to XSSF Tunnel
		TUNNEL_LOCKED = Mutex.new			# Manages accesses to TUNNEL
		TUNNEL_TIMEOUT= 10
		
		
		#								    TUNNEL
		#         	---------------------------------------------------------
		#			|  id  |     code     |   response   |      headers     |
		#			---------------------------------------------------------
		#			---------------------------------------------------------	
		#			|  01  |     AJAX     |   abcdefgh   |      headers     |
		#			---------------------------------------------------------	
		#			|  02  |     AJAX     |   xyzhrjeu   |      headers     |
		#			---------------------------------------------------------	
		#			|  ..  |     ....     |   ........   |   ............   |
		#
		#
		#   Tunnel = { 	'id' => [code, response, headers],
		#				'01' => [AJAX, abcdefgh, headers]}
		# 	When tunneled victim asks: concatenate and send all codes where (code != nil). Sets all sents to nil
    end
end


require 'msf/base/xssf/xssfbanner'
require 'msf/base/xssf/xssftunnel'
require 'msf/base/xssf/xssfdatabase'
require 'msf/base/xssf/xssfgui'
require 'msf/base/xssf/xssfmaster'
require 'msf/base/xssf/xssfserver'
require 'msf/base/xssf/webrickpatches'

