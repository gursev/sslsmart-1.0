# Gursev Singh Kalra @ Foundstone(McAfee)
# Please see LICENSE.txt for licensing information

class ResultContainer
  def initialize(status, data)
    @status = status
    @data   = data
  end

  attr_accessor :status, :data
end
