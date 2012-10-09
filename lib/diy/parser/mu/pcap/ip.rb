# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class IP < Packet
    IPPROTO_TCP      = 6
    IPPROTO_UDP      = 17
    IPPROTO_HOPOPTS  = 0
    IPPROTO_ROUTING  = 43
    IPPROTO_FRAGMENT = 44
    IPPROTO_AH       = 51
    IPPROTO_NONE     = 59
    IPPROTO_DSTOPTS  = 60
    IPPROTO_SCTP     = 132

    attr_accessor :src, :dst

    def initialize src=nil, dst=nil
        super()
        @src = src
        @dst = dst
    end

    def v4?
        return false
    end

    def v6?
        return false
    end

    def proto
        raise NotImplementedError
    end

    def pseudo_header payload_length
        raise NotImplementedError
    end

    def == other
        return super &&
            self.src    == other.src &&
            self.dst    == other.dst
    end

    def self.checksum bytes
        if bytes.size & 1 == 1
            bytes = bytes + "\0"
        end 
        sum = 0
        bytes.unpack("n*").each {|n| sum += n }
        sum = (sum & 0xffff) + (sum >> 16 & 0xffff)
        ~sum & 0xffff
    end
end

end
end
