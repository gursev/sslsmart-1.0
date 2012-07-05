# Gursev Singh Kalra @ Foundstone
require 'bin/sslsmartlib'

host = ARGV[0]
port = ARGV[1]

suites = OpenSSL::SSL.get_mod_cipher_suites("SSLv3:!NULL:!aNULL")
q = Net::HTTP.new(host,port)

suites.each do |suite, version, bits, klen|
	a = q.verify_ssl_config(version, suite, Net::HTTP::CONTENT, "/")
	case a.status
	when true
		print "\n[+] Accepted%7s  %-25s%5s bits  %-s" % [version, suite, bits, a.data.body]
	when false
		print "\n[-] Rejected%7s  %-25s%5s bits  %-s" % [version, suite, bits, a.data]
	end
end

