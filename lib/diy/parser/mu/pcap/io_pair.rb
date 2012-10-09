# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

# For emulating of a pair of connected sockets. Bytes written 
# with #write to one side are returned by a subsequent #read on 
# the other side.
#
# Use Pair.stream_pair to get a pair with stream semantics.
# Use Pair.packet_pair to get a pair with packet semantics.
class IOPair
    attr_reader :read_queue
    attr_accessor :other

    def initialize
        raise NotImplementedError
    end

    def self.stream_pair
        io1 = Stream.new
        io2 = Stream.new
        io1.other = io2
        io2.other = io1
        return io1, io2
    end

    def self.packet_pair
        io1 = Packet.new
        io2 = Packet.new
        io1.other = io2
        io2.other = io1
        return io1, io2
    end

    def write bytes
        @other.read_queue << bytes
        bytes.size
    end

    class Stream < IOPair
        def initialize 
            @read_queue = ""
        end

        def read n=nil
            n ||= @read_queue.size
            @read_queue.slice!(0,n)
        end
    end

    class Packet < IOPair
        def initialize 
            @read_queue = []
        end

        def read 
            @read_queue.shift
        end
    end

end
end
end

