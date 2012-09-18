require 'logger'

module DIY
  class Logger
    @@logger_container = []
    @@logger = ::Logger.new(STDOUT)
    @@logger.level = ::Logger::INFO
    @@logger.datetime_format = "%d-%b-%Y %H:%M:%S"
    @@logger_container.unshift @@logger
    class <<self
      def debug(*arg)
        @@logger_container.each do |logger|
          logger.debug(*arg)
        end
      end
      
      def info(*arg)
        @@logger_container.each do |logger|
          logger.info(*arg)
        end
      end
      
      def warn(*arg)
        @@logger_container.each do |logger|
          logger.warn(*arg)
        end
      end
      
      def error(*arg)
        @@logger_container.each do |logger|
          logger.error(*arg)
        end
      end
      
      def set(logger)
        @@logger = logger
        clear_and_add(logger)
      end
      
      def level=(level)
        @@logger_container.each do |logger|
          logger.level = level
        end
      end
      
      def add(logger)
        @@logger_container << logger
      end
      alias << add
      
      def clear
        @@logger_container.clear
      end
      
      def clear_and_add(logger)
        clear
        add(logger)
      end
    end
    
  end
end