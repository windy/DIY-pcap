require 'logger'

module DIY
  class Logger
    @@logger = ::Logger.new(STDOUT)
    @@logger.level = ::Logger::DEBUG
    @@logger.datetime_format = "%d-%b-%Y %H:%M:%S"
    class <<self
      def debug(*arg)
        @@logger.debug(*arg)
      end
      
      def info(*arg)
        @@logger.info(*arg)
      end
      
      def warn(*arg)
        @@logger.warn(*arg)
      end
      
      def error(*arg)
        @@logger.error(*arg)
      end
      
      def set(logger)
        @@logger = logger
      end
    end
    
  end
end