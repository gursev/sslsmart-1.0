# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

# require 'sslsmartlib'
# require 'singleton'
# require 'uri'
require 'resultcontainer'
require 'sslsmartconfig'

$conf   = SSLSmartConfig.instance

class UrlResults
  def initialize()
    @cert                     = nil
    @cert_validity            = nil
    @progress                 = 0
    @cipher_response_array    = []
  end


  def add_cipher_response(index, response)
    @cipher_response_array[index]  = response
  end


  def update_progress
    @progress                     = (@cipher_response_array.compact.length*100)/$conf.count_to_test if(@cipher_response_array)
  end

  attr_accessor :cert, :cert_validity, :cipher_response_array, :progress
end

class SSLSmartDB

  def initialize()
    @db     = {}
  end


  def add_url(url)
    return if(url == "" || url == nil)
    @db[url.to_sym] = UrlResults.new
  end


  def add_cert(url, cert, cert_validity)
    return if(url == "" || url == nil)
    return unless(@db[url.to_sym])
    @db[url.to_sym].cert          = cert
    @db[url.to_sym].cert_validity = cert_validity
    @db[url.to_sym].progress = ($conf.count_to_test == 0)?100:1
  end


  def add_cipher_response(url, index, response)
    return if(url == "" || url == nil)
    @db[url.to_sym].add_cipher_response(index, response)
    @db[url.to_sym].update_progress()
  end


  def cert_valid?(url)
    return nil if(url == "" || url == nil)
    return nil unless(@db[url.to_sym])
    @db[url.to_sym].cert_validity
  end

  
  def get_cert(url)
    return nil if(url == "" || url == nil)
    return nil unless(@db[url.to_sym])
    @db[url.to_sym].cert
  end

  
  def get_response(url, index)
    return nil if(url == "" || url == nil)
    return nil unless(@db[url.to_sym])
    response = @db[url.to_sym].cipher_response_array[index]
    return nil unless(response)
    #return nil unless(response.data)
    response
  end

  
  def get_html_response(url, index)
    return nil if(url == "" || url == nil)
    response    = get_response(url, index)
    return nil unless(response)
    return nil unless(response.status)
    if(response.data)
      return response.data.body
    else
      return ""
    end
  end

  
  def get_text_response(url, index)
    return nil if(url == "" || url == nil)
    response  = get_response(url, index)
    return nil unless(response)
    return nil unless(response.status)

    return "" unless(response.data)
    response  = response.data
    
    text      = ""
    text      = "HTTP\/#{response.http_version} #{response.code} #{response.msg}\n"
    response.each do |header, body|
      text    << "#{header}: #{body}\n"
    end
    text      << "\n\n"
    text      << response.body
    text
  end


  def get_response_code(url, index)
    return nil if(url == "" || url == nil)
    response  = get_response(url, index)
    # REVIEW HERE
    return nil unless(response)
    return "" unless(response.data)

    retval    = response.data
    case response.status
    when true
      return "HTTP\/#{retval.http_version} #{retval.code} #{retval.msg}"
    when false
      return retval.message
    else
      return nil
    end
  end


  def get_all_cipher_results(url)
    return nil if(url == "" || url == nil)
    return nil unless(@db[url.to_sym])
    @db[url.to_sym].cipher_response_array
  end


  def get_progress(url)
    return 0 if(url == "" || url == nil)
    return 0 unless(@db[url.to_sym])
    @db[url.to_sym].progress 
  end

end
