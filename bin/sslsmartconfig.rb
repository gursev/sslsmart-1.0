# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

require 'singleton'
require 'sslsmartlib'
require 'sslsmartlog'

$log  = SSLSmartLog.instance

class CipherSuite
  def initialize(version, name, bits)
    @test     = true
    @version  = version
    @name     = name
    @bits     = bits
  end
  
  def test=(val)
    case val
    when true, false
      @test = val
    end
  end

  def test?
    @test
  end

  def to_s
    "test = #{@test}\tversion = #{@version}\tbits = #{@bits}\tname = #{@name}"
  end


  # Sort with version, bits and then name
  def <=>(obj)
    if((version <=>obj.version) == 0)
      if((bitcomp = (obj.bits.to_i <=> bits.to_i)) == 0)
        return name <=> obj.name
      else
        return bitcomp
      end
    else
       version <=> obj.version
    end
  end

  def +(cs)
    @bits = "--"
    @name = @name + ":" + cs.name
    self
  end

  attr_reader :version, :name, :bits, :test
end

class SSLSmartConfig
  SCAN_TYPES        = ["Connect", "Content"]
  SCAN_MODES        = ["Test Individual Ciphers", "SSL Version Check (Faster)"]
  include Singleton

  def initialize
    @urls           = []
    @cipher_suites  = []
    @sslv2          = true
    @sslv3          = true
    @tlsv1          = true
    @scan_type      = SCAN_TYPES[1]     # Content or Connect
    @scan_mode      = SCAN_MODES[0]     # Cipher or version check
    @proxy_add      = nil
    @proxy_port     = nil
    @rootcert_path  = File.join(File.expand_path("."), "rootcerts.pem")
    @filter         = nil
  end

  attr_reader :urls, :cipher_suites, :sslv2, :sslv3, :tlsv1, :scan_type, :proxy_add, :proxy_port, :rootcert_path, :filter, :scan_mode
  attr_writer :cipher_suites

  def update_test_status(cs)
    case cs.version
    when "SSLv2"
      cs.test         = @sslv2
    when "SSLv3"
      cs.test         = @sslv3
    when "TLSv1"
      cs.test         = @tlsv1
    end
  end

  def update_version_test_status()
    @cipher_suites.each do |cs|
      update_test_status(cs)
    end
  end

  def index_for_version(version)
    @cipher_suites.each_with_index do |x, index|
      return index if(x.version == version)
    end
    nil
  end
  
  def update_config(config_hash)
    return unless(config_hash.class == Hash)
    $log.info("Updating configuration with #{config_hash.inspect}")
    config_hash.each do |key, value|
      case key
      when :urls
        @urls           = value
      when :cipher_suites
        @cipher_suites  = value
      when :sslv2
        @sslv2          = value
        update_version_test_status()
      when :sslv3
        @sslv3          = value
        update_version_test_status()
      when :tlsv1
        @tlsv1          = value
        update_version_test_status()
      when :scan_type
        @scan_type      = SCAN_TYPES[value] if(SCAN_TYPES[value])
      when :proxy_add
        @proxy_add       = value
      when :proxy_port
        @proxy_port      = value
      when :rootcert_path
        @rootcert_path   = value
      when :filter
        begin
          cipher_suites = OpenSSL::SSL.get_mod_cipher_suites(value)
        rescue => ex
          raise ex
        end
        @filter             = value
        @cipher_suites.clear
        
        case @scan_mode
        when SCAN_MODES[0]
          cipher_suites.each do |x|
            cs                = CipherSuite.new(x[1], x[0], x[2].to_s)
            update_test_status(cs)
            @cipher_suites << cs
          end
        when SCAN_MODES[1]
          cipher_suites.each do |xmode|
            newsuite  = CipherSuite.new(xmode[1], xmode[0], xmode[2].to_s)
            idx       = index_for_version(newsuite.version)
            if(idx)
              @cipher_suites[idx] = @cipher_suites[idx] + newsuite
            else
              update_test_status(newsuite)
              @cipher_suites << newsuite
            end

          end
        end

        @cipher_suites.sort!
      when :scan_mode
        @scan_mode      = SCAN_MODES[value] if(SCAN_MODES[value])
      end
    end
  end


  def count_to_test()
    count = 0
    cipher_suites.each do |x|
      count += 1 if(x.test?)
    end
    count
  end

end

CONF  = SSLSmartConfig.instance
CONF.update_config({:filter => "DEFAULT"})
