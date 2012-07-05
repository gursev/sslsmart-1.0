# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

require 'net/https'
require 'singleton'
require 'uri'
require 'resultcontainer'
require 'sslsmartlog'

$log = SSLSmartLog.instance

  module OpenSSL
    module SSL
      if(RUBY_VERSION =~ /^1\.8\.6/)
        class SSLContext
          RAW     = 0
          SPLIT   = 1
          DEFAULT_PARAMS = {
            :verify_mode => OpenSSL::SSL::VERIFY_PEER,
            :ciphers => "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW",
            :options => OpenSSL::SSL::OP_ALL,
          }


          def set_params(params={})
            begin
              $log.debug("Setting parameters #{params.inspect}") if(params!= {})
              params = DEFAULT_PARAMS.merge(params)
              params.each do|name, value|
                next if(name == :ssl_version) #1.8.6 does not have ssl_version method
                self.__send__("#{name}=", value)
              end
            rescue => ex
              $log.error("#{ex.class}\t#{ex.message}")
              raise
            end
            return params
          end

        end

      end #End of if(RUBY_VERSION =~ /^1\.8/)

      
      def SSL.get_cipher_suites(filter)
        $log.debug("requesting cipher suites with filter")
        # Making the filters case insensitive
        filter                = filter.gsub(/tlsv1/i, "TLSv1").gsub(/sslv3/i, "SSLv3").gsub(/sslv2/i, "SSLv2")
        version               = :SSLv23
        begin
          # RUBY 1.8.6 OpenSSL api is not compatible with 1.9 for purpose required here
          # Using the existing implementation to get ciphers suites
          ncontext            = OpenSSL::SSL::SSLContext.new
          ohash               = {:ciphers => filter, :ssl_version => version}
          ncontext.set_params(ohash)
          return ncontext.ciphers
        rescue => ex
          $log.error(ex.message)
          raise ex
        end
      end

      
      def SSL.get_mod_cipher_suites(filter)
        $log.debug("requesting modified cipher suites with filter")
        begin
          suites = OpenSSL::SSL.get_cipher_suites(filter)
        rescue => ex
          $log.error(ex.message)
          raise ex
        end
        
        sslv2   = []
        sslv3   = []
        tlsv1   = []
        suites.each do |x|
          case x[1]
          when "SSLv2"
            sslv2 << x
          when "TLSv1/SSLv3"
            #Suite Name -- Version -- Key Length -- Cipher Supported Key Length
            sslv3 << [x[0], "SSLv3", x[2],x[3]]
            tlsv1 << [x[0], "TLSv1", x[2],x[3]]
          end
        end
        sslv2 + sslv3 + tlsv1
      end

    end
  end


module Net
  class HTTP
    # Required for Ruby 1.9 support.
    attr_accessor  :enable_post_connection_check
  end
end

module Net
  class HTTP

    CONNECT           = 0
    CONTENT           = 1
    CA_ROOT_BUNDLE  = "rootcerts.pem"
    

    # Verifies a given SSL configuration. It performs
    # Few valid function calls
    # rq.verify_ssl_config(:SSLv2, nil, Net::HTTP::CONTENT, "/")
    # rq.verify_ssl_config(:SSLv3, ["AES256-SHA", "DES-CBC3-SHA","EXP-RC2-CBC-MD5"], Net::HTTP::CONTENT, "/")
    # rq.verify_ssl_config(:SSLv3, "AES256-SHA", Net::HTTP::CONTENT, "/")
    def verify_ssl_config(version, cipher_suite, scan_type, *args)
      $log.debug("Verifying ssl configuration #{version}\t#{cipher_suite}\t#{scan_type}")
      set_ssl_config(version, cipher_suite)
      disable_validations

      case scan_type
      when CONNECT
        return self.ssl_connect
      when CONTENT
        begin
          response = self.get(*args)
          return ResultContainer.new(true, response)
        rescue OpenSSL::SSL::SSLError => ex
          return ResultContainer.new(false, ex)
        rescue => ex1
          return ResultContainer.new(false, ex1)
        end
      end

    end

    # Set SSL configuration for an HTTP Request.
    # version provides the SSL version to be used for request. The value can be :SSLv2, :SSLv3, TLSv1 or SSLv23
    # cipher_suite accepts the value of cipher suite to be used for a given request.
    # The cipher suite values supported for a give version can be obtained by Net::HTTP::get_ssl_ciphers or Net::HTTP::get_ssl_ciphers_and_keylen class methods
    def set_ssl_config(version, cipher_suite = nil)
      $log.debug("Setting ssl configuration #{version}, #{cipher_suite}")
      self.use_ssl                      = true

      self.set_context                  = version
      if(self.respond_to?(:ssl_version)) # For Ruby 1.9
        self.ssl_version = version
      end
      self.ciphers                      = cipher_suite if(cipher_suite)
      disable_validations
    end


    # Returns SSL Certificate details
    def get_cert_details()
      $log.debug("Returning certificate details")
      self.use_ssl                      = true
      disable_validations
      begin
        self.start do |x|
          return ResultContainer.new(true, x.peer_cert)
        end
      rescue => ex
        return ResultContainer.new(false, ex)
      end
    end


    # PATH to Bundle of CA Root Certificates  has to be prvided as a ca_root_bundle parameter.
    # Mozilla Firefox Bundle of CA Root Certificates can be downloade from http://curl.haxx.se/ca/cacert.pem for your own use.
    def verify_cert(ca_root_bundle = CA_ROOT_BUNDLE)
      $log.debug("Verifying certificate")
      ca_root_bundle = CA_ROOT_BUNDLE unless(ca_root_bundle)
      unless (File.exist?(ca_root_bundle) && File.file?(ca_root_bundle))
        return ResultContainer.new(false, "Invalid certificate file #{ca_root_bundle}")
      end

      self.use_ssl                      = true
      enable_validations
      self.ca_file  = ca_root_bundle
      begin
        self.start do |x|
          x.peer_cert
          return ResultContainer.new(true, x.peer_cert)
        end
      rescue => ex
        return ResultContainer.new(false, ex)
      end
    end


    # This block supports connect scans only
    def ssl_connect()
      $log.debug("Initiating SSL Connect Test")
      disable_validations
      s = timeout(@open_timeout) { TCPSocket.open(conn_address(), conn_port()) }
      s = OpenSSL::SSL::SSLSocket.new(s, @ssl_context)
      s.sync_close = true

      @socket = BufferedIO.new(s)
      @socket.read_timeout = @read_timeout
      @socket.debug_output = @debug_output

      if proxy?
        @socket.writeline sprintf('CONNECT %s:%s HTTP/%s', @address, @port, HTTPVersion)
        @socket.writeline "Host: #{@address}:#{@port}"
        @socket.writeline ''
        HTTPResponse.read_new(@socket).value
      end

      begin
        s.connect
        return ResultContainer.new(true, nil)
      rescue OpenSSL::SSL::SSLError => ex
        return ResultContainer.new(false, ex)
      rescue => ex2
        return ResultContainer.new(false, ex2)
      end
    end


    def enable_validations
      #$log.debug("Enabling all validations")
      self.enable_post_connection_check = true
      verify_peer
    end


    def disable_validations
      #$log.debug("Disabling all validations")
      self.enable_post_connection_check = false
      verify_none
    end


    # Turns on certificate validation for given HTTP request. If not used, a warning will be seen during the enumeration.
    def verify_peer
      #$log.debug("Enabling peer verification")
      self.verify_mode = OpenSSL::SSL::VERIFY_PEER
    end

    
    # Turns off certificate validation for given HTTP request. If not used, a warning will be seen during the enumeration.
    def verify_none
      #$log.debug("Disabling peer validation")
      self.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end


    # Sets context for a given HTTP request. The values accepted are any of valid SSL versions
    def set_context=(value)
      $log.debug("Setting context to #{value}")
      @ssl_context ||= OpenSSL::SSL::SSLContext.new #Create a new context
      @ssl_context &&= OpenSSL::SSL::SSLContext.new(value)
    end

    
    # Creating a private which allows ciphers to be set for a given HTTP request.
    if RUBY_VERSION =~ /^1\.8/
      ssl_context_accessor :ciphers
    end

  end
end

# Single unified interface to generate ciphers for OpenSSL filters
def get_cipher_suites(filter)

  $log.debug("Requesting for get_cipher_suites standalone method of SSLSmartLib")
  version               = :SSLv23
  begin
  # RUBY 1.8.6 OpenSSL api is not compatible with 1.9 for purpose required here
  # Using the existing implementation to get ciphers suites
  if(RUBY_VERSION =~ /^1\.8/)
    rq                  = Net::HTTP.new('dummy')
    rq.set_ssl_config(version, filter) # Either this line of the three commented lines do the JOB
    return rq.ciphers
  elsif(RUBY_VERSION =~ /^1\.9/)
    # RUBY 1.9 library call does not return cipher array when ciphers function is called on an HTTP object.
    # The code below talks directly to OpenSSL Library and extracts the information.
    ncontext            = OpenSSL::SSL::SSLContext.new
    ohash               = {:ciphers => filter, :ssl_version => version}
    ncontext.set_params(ohash)
    return ncontext.ciphers
  end
  rescue => ex
    $log.error(ex.message)
    raise ex
  end
end
