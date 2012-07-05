# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

require 'logger'
require 'singleton'

class SSLSmartLog
  include Singleton
  def initialize
    @logfile        = Logger.new('SSLSmart.log', 'daily')
    @logfile.level  = Logger::INFO
    #@logfile.level  = Logger::DEBUG
  end

  def fatal(message)
    @logfile.fatal(message)
  end

  def error(message)
    @logfile.error(message)
  end

  def warn(message)
    @logfile.warn(message)
  end

  def info(message)
    @logfile.info(message)
  end

  def debug(message)
    @logfile.debug(message)
  end

end
