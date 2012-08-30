require 'eventmachine'


module DIY
  class Sender < EM::Connection
    def notify_readable(*arg)
    end
    
  end
end