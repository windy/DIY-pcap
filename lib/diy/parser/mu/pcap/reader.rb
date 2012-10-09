# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class Reader
    attr_accessor :pcap2scenario

    FAMILY_TO_READER = {}

    # Returns a reader instance of specified family. Returns nil when family is :none.
    def self.reader family
        if family == :none
            return nil
        end

        if klass = FAMILY_TO_READER[family]
            return klass.new
        end

        raise ArgumentError, "Unknown protocol family: '#{family}'"
    end

    # Returns family name 
    def family
        raise NotImplementedError
    end

    # Notify parser of bytes written. Parser may update state
    # to serve as a hint for subsequent reads.
    def record_write bytes, state=nil
        begin
            do_record_write bytes, state
        rescue
            nil
        end
    end

    # Returns next complete message from byte stream or nil. 
    def read_message bytes, state=nil
        read_message! bytes.dup, state
    end

    # Mutating form of read_message. Removes a complete message
    # from input stream. Returns the message or nil if there. 
    # is not a complete message.
    def read_message! bytes, state=nil
        begin
            do_read_message! bytes, state
        rescue
            nil
        end
    end

end
end
end

require 'mu/pcap/reader/http_family'
