class AddXssf < ActiveRecord::Migration

	def self.up
		create_table :xssf_victims do |t|
			t.integer   :xssf_server_id, :required => true
			t.boolean	:active
			t.string    :ip
			t.integer	:interval
			t.string	:location
			t.datetime	:first_request
			t.datetime  :last_request
			t.boolean	:tunneled
			t.string	:browser_name
			t.string	:browser_version
			t.string	:os_name
			t.string	:os_version
			t.string	:arch
			t.string	:current_attack_url
			t.string	:cookie
		end
		
		create_table :xssf_waiting_attacks do |t|
			t.integer   :xssf_victim_id, :required => true
			t.string	:url
			t.string	:name
		end

		create_table :xssf_logs do |t|
			t.integer   :xssf_victim_id, :required => true
			t.datetime	:time
			t.string	:result	
			t.string	:name
		end


		create_table :xssf_servers do |t|
			t.string	:host
			t.integer	:port
			t.string	:uri
			t.boolean	:active
		end
	end

	
	def self.down
		drop_table :xssf_victims
		drop_table :xssf_waiting_attacks
		drop_table :xssf_servers
		drop_table :xssf_logs
	end
end