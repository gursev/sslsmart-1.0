# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

require 'rubygems'
require 'sslsmartlib'
require 'sslsmartconfig'
require 'sslsmartdb'
require 'uri'
require 'cgi'
require 'builder'
require 'socket'
require 'sslsmartlog'

$log  = SSLSmartLog.instance
$conf = SSLSmartConfig.instance

MAX_THREADS     = 3
MAX_THREAD_TIME = 10
class SSLSmartController < SSLSmartDB
  def initialize()
    super()
  end

  def start_test()
    $log.debug("Starting SSLSmart Test")
    begin
      thr = []
      $conf.urls.each_with_index do |url, url_index|
        $log.info("Starting Test for #{url}")
        purl            = URI.parse(url)
        path_query      = (purl.query == nil || purl.query == "") ? "#{purl.path}" : "#{purl.path}?#{purl.query}"
        add_url(url)

        begin
          Socket.gethostbyname(purl.host) # An exception is raised if this fails and is logged
          rq            = Net::HTTP.new(purl.host, purl.port, $conf.proxy_add, $conf.proxy_port)
          rq.use_ssl    = true
          rq.disable_validations
          rq.get("#{path_query}")
        rescue SocketError => ex
          $log.error("#{ex.class}\t#{purl.host}\t#{ex.message}")
          next
        rescue => ex
          $log.error("#{ex.class}\t#{purl.host}\t#{ex.message}")
          next
        end

        rq            = Net::HTTP.new(purl.host, purl.port, $conf.proxy_add, $conf.proxy_port)
        cert_details  = rq.get_cert_details
        $log.debug("Certificate Retrieved for #{purl.host}:#{purl.port}")
        rq            = Net::HTTP.new(purl.host, purl.port, $conf.proxy_add, $conf.proxy_port)
        cert_validity = rq.verify_cert($conf.rootcert_path)
        $log.debug("Certificate Vefified for #{purl.host}:#{purl.port}")
        add_cert(url, cert_details, cert_validity)
        yield url, url_index, nil if(block_given?)

        #rq            = Net::HTTP.new(purl.host, purl.port, $conf.proxy_add, $conf.proxy_port)
        
        $conf.cipher_suites.each_with_index do |cipher_suite, suite_index|
          $log.debug("Starting Threads")
          thr << Thread.new do
            next unless(cipher_suite.test?)
            $log.debug("Testing #{url} with #{cipher_suite}")
            rq            = Net::HTTP.new(purl.host, purl.port, $conf.proxy_add, $conf.proxy_port)
            response      = rq.verify_ssl_config(cipher_suite.version, cipher_suite.name, SSLSmartConfig::SCAN_TYPES.index($conf.scan_type), "#{path_query}")
            add_cipher_response(url, suite_index, response)
            yield url, url_index, suite_index if(block_given?) #"#{cipher_suite.version}\t#{cipher_suite.bits}\t#{cipher_suite.name}\t\t#{response.status}"
          end #End of thread

          t1 = Time.now
          if(thr.length >= MAX_THREADS)
            thr.each do |x|
              if(Time.now - t1 > MAX_THREAD_TIME)
                x.terminate
                $log.warn "Thread killed"
              end
              x.join
            end
            thr.clear
          end
          
        end
        $log.debug("Ending Test for #{url}")
      end

    rescue => ex
      $log.fatal(ex.message)
      $log.fatal(ex.backtrace)
      raise
    end
  end

#  def show_results()
#    $conf.urls.each do |url|
#      puts "#{url}"
#      puts "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
#      puts get_cert(url.to_sym).data.to_text
#      puts cert_valid?(url.to_sym).status
#      $conf.cipher_suites.each_with_index do |cipher_suite, suite_index|
#        next unless(cipher_suite.test?)
#        print "#{cipher_suite}\t#{suite_index}\t"
#        puts "#{get_response(url, suite_index).status}" if(get_response(url, suite_index))
#      end
#    end
#
#  end


  def create_report(type)
    case type
    when :text, :textv
      return create_text_report(type)
    when :xml, :xmlv
      return create_xml_report(type)
    when :html, :htmlv
      return create_html_report(type)
    end

  end
  
  #WORKING GET_TEXT_REPORT FUNCTION
  def create_text_report(type)
    $log.debug("Creating text report")
    return nil unless(type == :text || type == :textv)
    tr = ""
    tr << %q{
         ___ ___ _    ___                _     ___             _ _
        / __/ __| |  / __|_ __  __ _ _ _| |_  | _ \___ ____  _| | |_ ___
        \__ \__ \ |__\__ \ '  \/ _` | '_|  _| |   / -_|_-< || | |  _(_-<
        |___/___/____|___/_|_|_\__,_|_|  \__| |_|_\___/__/\_,_|_|\__/__/

      }
    $conf.urls.each do |url|
      next if(self.get_progress(url) == 0)
      tr << "\n#{url}\n"
      tr << "-"*80
      if(results = get_all_cipher_results(url))
        results.each_with_index do |result, suite_index|
          next unless(result)
          case result.status
          when true
            tr << "\n[+] Accepted%7s  %-25s%5s bits  %-s" % [$conf.cipher_suites[suite_index].version, $conf.cipher_suites[suite_index].name, $conf.cipher_suites[suite_index].bits, get_response_code(url, suite_index)]
            if(type == :textv)
              resp = get_text_response(url, suite_index)
              tr << "\n%s\n" % [resp] if(resp)
            end
          when false
            tr << "\n[-] Rejected%7s  %-25s%5s bits  %-s" % [$conf.cipher_suites[suite_index].version, $conf.cipher_suites[suite_index].name, $conf.cipher_suites[suite_index].bits, get_response_code(url, suite_index)]
          end
        end
      end

      if(cert_validity = cert_valid?(url))
        case cert_validity.status
        when true
          tr << "\n\n[+] Valid Digital Certificate\n"
        when false
          tr << "\n\n[-] Invalid Digital Certificate. "
          tr <<  "#{cert_validity.data.message}\n" if(cert_validity.data)
        end
      end
      cert = get_cert(url)
      if(type == :textv)
        tr << cert.data.to_text if(cert && cert.data)
      else
        if(cert && cert.data)
          tr  << "\t%-20s\t:%s"   % ["Certificate Subject", cert.data.subject]
          tr  << "\n\t%-20s\t:%s" % ["Certificate Issuer", cert.data.issuer]
          tr  << "\n\t%-20s\t:%s" % ["Valid Not Before", cert.data.not_before]
          tr  << "\n\t%-20s\t:%s" % ["Valid Not After", cert.data.not_after]
        end
      end
      tr << "\n\n"
    end
    tr << "\n\n"
    tr
  end

  #WORKING GET_TEXT_REPORT FUNCTION
  def create_html_report(type)
    $log.debug("Creating html report")
    return nil unless(type == :html || type == :htmlv)
    tr = ""
    tr << "<html><head><title>SSLSmart Results</title></head>\n<body>"
    tr << "\n<h1 align='center'>SSLSmart Results</h1>"
    $conf.urls.each do |url|
      next if(self.get_progress(url) == 0)
      tr << "\n"
      tr << '<table width="80%" border="1" cellpadding="0" cellspacing="0">'
      tr << "\n<tr align='center'><td colspan='5' bgcolor=#A4A4A4><h3>#{url}</h3></td></tr>"
      if(results = get_all_cipher_results(url))
        tr << "<tr bgcolor=#BDBDBD>
          <td><b>Supported?</b></td>
          <td><b>Version</b></td>
          <td><b>Cipher Suite</></td>
          <td><b>Bits</b></td>
          <td><b>Response Code</b></td>
        </tr>
        " if(results.length > 0)
        results.each_with_index do |result, suite_index|
          next unless(result)
          case result.status
          when true
            tr << "<tr >
                  <td>Yes</td>
                  <td>#{$conf.cipher_suites[suite_index].version}</td>
                  <td>#{$conf.cipher_suites[suite_index].name}</td>
                  <td>#{$conf.cipher_suites[suite_index].bits}</td>
                  <td>#{get_response_code(url, suite_index)}</td>
                </tr>"
            if(type == :htmlv)
              resp = get_text_response(url, suite_index)
              if(resp)
                resp = CGI.escapeHTML(resp)
                resp = resp.gsub(/[\n\r]/,'<br/>')
                tr << "\n<tr><td colspan='5'><font size='2'>#{resp}</font></td></tr>"
              end
            end
          when false
            tr << "<tr>
                  <td>No</td>
                  <td>#{$conf.cipher_suites[suite_index].version}</td>
                  <td>#{$conf.cipher_suites[suite_index].name}</td>
                  <td>#{$conf.cipher_suites[suite_index].bits}</td>
                  <td>#{get_response_code(url, suite_index)}</td>
                </tr>"
          end
        end
      end
      
      cert      = get_cert(url)
      validity  = ""
      if(cert && cert.data)
        if(cert_validity = cert_valid?(url))
          case cert_validity.status
          when true
            validity << "Valid Digital Certificate"
          when false
            validity << "Invalid Digital Certificate.&nbsp;"
            validity <<  "#{cert_validity.data.message}\n" if(cert_validity.data)
          end
        end

        tr << "<tr><td colspan='5' align='center' bgcolor=#BDBDBD><b>Certificate Details</b></td></tr>\n"
        tr << "<tr><td colspan='2'><b>Validity</b></td><td colspan='3'>#{validity}    </td></tr>\n"
        tr << "<tr><td colspan='2'><b>Subject           </b></td><td colspan='3'>#{cert.data.subject}    </td></tr>\n"
        tr << "<tr><td colspan='2'><b>Issuer            </b></td><td colspan='3'>#{cert.data.issuer}     </td></tr>\n"
        tr << "<tr><td colspan='2'><b>Valid Not before  </b></td><td colspan='3'>#{cert.data.not_before} </td></tr>\n"
        tr << "<tr><td colspan='2'><b>Valid Not After   </b></td><td colspan='3'>#{cert.data.not_after}  </td></tr>\n"
        if(type == :htmlv)
          tr << "<tr><td colspan='2'><b>Version   </b></td><td colspan='3'>#{cert.data.version}</td></tr>\n"
          tr << "<tr><td colspan='2'><b>Serial Number   </b></td><td colspan='3'>#{cert.data.serial}  </td></tr>\n"
          tr << "<tr><td colspan='2'><b>Signature Algorithm</b></td><td colspan='3'>#{cert.data.signature_algorithm}  </td></tr>\n"
          cert.data.extensions.each do |extn|
            extns = extn.to_s.split("=")
            tr << "<tr><td colspan='2'><b>#{extns[0]}</b></td><td colspan='3'>#{extns[1]} </td></tr>\n"
          end
          tr << "<tr><td colspan='2'><b>Public Key</b></td><td colspan='3'>#{cert.data.public_key.to_text.gsub(/\n/,'<br/>')}  </td></tr>\n"
        end
      end
      
      tr << "</table><br/><br/>\n"

    end
    tr << "</body>\n</html>"
    tr
  end

  
  def create_xml_report(type)
    $log.debug("Creating XML report")
    return nil unless(type == :xml || type == :xmlv)
    tr = ""
    xm = Builder::XmlMarkup.new(:target => tr, :indent => 2)
    xm.instruct!

    xm.SSLSmart {
      $conf.urls.each do |url|
        next if(self.get_progress(url) == 0)
        
        xm.url("value" => url) {
          if(results = get_all_cipher_results(url))
            results.each_with_index do |result, suite_index|
              next unless(result)

              if(result.status == true || result.status == false)
                xm.cipher_suite {
                  xm.version($conf.cipher_suites[suite_index].version)
                  xm.name($conf.cipher_suites[suite_index].name)
                  xm.bits($conf.cipher_suites[suite_index].bits)
                  xm.supported(result.status)
                  xm.response_code(get_response_code(url, suite_index))
                  if(type == :xmlv)
                    xm.full_response{
                      xm.cdata!(CGI.escapeHTML(get_text_response(url, suite_index))) if(get_text_response(url, suite_index))
                    }
                  end
                }
              end
            end
          end # END OF if(results = get_all_cipher_results(url))

          cert          = get_cert(url)
          validity_msg  = ""
          validity      = ""
          if(cert && cert.data)
            if(cert_validity = cert_valid?(url))
              validity  = cert_validity.status
              case cert_validity.status
              when true
                validity_msg << "Valid Digital Certificate"
              when false
                validity_msg << "Invalid Digital Certificate.&nbsp;"
                validity_msg <<  "#{cert_validity.data.message}\n" if(cert_validity.data)
              end
            end

          xm.certificate {
            xm.validity(validity)
            xm.validity_msg(validity_msg)
            xm.subject(cert.data.subject)
            xm.issuer(cert.data.issuer)
            xm.not_before(cert.data.not_before)
            xm.not_after(cert.data.not_after)
            if(type == :xmlv)
              xm.version(cert.data.version)
              xm.serial(cert.data.serial)
              xm.signature_algorithm(cert.data.signature_algorithm)
              if(cert.data.extensions)
                xm.x509extensions {
                  cert.data.extensions.each do |extn|
                    extns = extn.to_s.split("=", 2)
                    xm.extension {
                      xm.name(extns[0])
                      xm.value(extns[1])
                    }
                  end
                }
              end
              xm.public_key{
                xm.cdata!(cert.data.public_key.to_text)
              }
            end
          }
          end
        }
      end # END OF $conf.urls.each do |url|
    }
    tr
  end
end
