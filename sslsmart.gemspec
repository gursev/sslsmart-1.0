# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

require 'rubygems'
SPEC = Gem::Specification.new do |s|
	s.name 				= 'sslsmart'
	s.version 			= '1.0'
	s.authors			= ['Gursev Singh Kalra']
	s.email				= %q{gursev.kalra@foundstone.com}
	s.files				= ['bin/fs_icon_32.ico', 'bin/resultcontainer.rb', 'bin/rootcerts.pem', 'bin/sslsmartconfig.rb', 'bin/sslsmartcontroller.rb', 'bin/sslsmartdb.rb', 'bin/sslsmartgui.rb', 'bin/sslsmartlib.rb', 'bin/sslsmartlog.rb', 'bin/sslsmartmisc.rb', 'sslsmart.gemspec', 'README', 'sample.rb', 'LICENSE.txt']
	s.homepage			= 'http://www.foundstone.com'
	s.platform			= Gem::Platform::RUBY
	s.require_paths 		= ["bin"]
	s.summary			= 'SSLSmart is a smart SSL cipher enumeration tool'
	s.description		= 'SSLSmart is an advanced and highly flexible Ruby based smart SSL cipher enumeration tool'
	s.rubyforge_project = 'none'
	s.add_dependency("wxruby", ">=2.0.0")
	s.add_dependency("builder", ">=2.1.2")
	
end
