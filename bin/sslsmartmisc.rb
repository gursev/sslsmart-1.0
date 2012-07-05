# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

require 'uri'
require 'sslsmartlog'

$log = SSLSmartLog.instance

module SSLSmartMisc

  def convert_to_url(line)
    line.strip!
    if(line == "")
      $log.warn("No hostname provided")
      return nil
    end

    line.sub!(/^https?:\/\//,"") if(line =~ /^https?:\/\//)
    line[0,0] = 'https://'
    begin
      uri = URI.parse(line)
    rescue URI::Error => e
      $log.warn(e.message)
      return nil
    end

    uri.path = "/" if(uri.path == "")
    uri.to_s

  end


  def get_urls_from_file(filename)

    unless(File.file?(filename))
      $log.error("Invalid Filename #{filename}")
      return nil
    end

    urls = []
    File.open(filename) do |f|
      f.each do |line|
        url = convert_to_url(line) if(line.strip != "")
        urls << url if(url)
      end
    end
    urls
  end

end
