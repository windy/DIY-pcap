# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'mu/pcap/io_pair'

module Mu
class Pcap
class IOWrapper
    attr_reader :ios, :unread, :state

    def initialize ios, reader
        @ios       = ios
        @reader    = reader
        # parse state for reader
        @state     = {}
        # read off of underlying io but not yet processed by @reader
        @unread    = "" 
    end

    # Impose upper limit to protect against memory exhaustion.
    MAX_RECEIVE_SIZE = 1048576 # 1MB

    # Returns next higher level protocol message.
    def read
        until message = @reader.read_message!(@unread, @state)
            bytes = @ios.read
            if bytes and not bytes.empty?
                @unread << bytes
            else
                return nil 
            end
            if @unread.size > MAX_RECEIVE_SIZE 
                raise "Maximum message size (#{MAX_RECEIVE_SIZE}) exceeded"
            end
        end

        return message
    end

    # Parser may need to see requests to understand responses.
    def record_write bytes
        @reader.record_write bytes, @state
    end

    def write bytes, *args
        w = @ios.write bytes, *args
        record_write bytes
        w
    end

    def write_to bytes, *args
        w = @ios.write_to bytes, *args
        record_write bytes
        w
    end

    def open  
        if block_given?
            @ios.open { yield }
        else
            @ios.open
        end
    end

    def open?
        @ios.open?
    end

    def close
        @ios.close
    end
    
end
end
end
