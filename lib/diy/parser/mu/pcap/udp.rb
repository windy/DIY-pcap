# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class UDP < Packet
    attr_accessor :src_port, :dst_port

    def initialize src_port=0, dst_port=0
        super()
        @src_port = src_port
        @dst_port = dst_port
    end

    def flow_id
        return [:udp, @src_port, @dst_port]
    end

    FMT_nnnn = 'nnnn'
    def self.from_bytes bytes
        bytes_length = bytes.length
        bytes_length >= 8 or
            raise ParseError, "Truncated UDP header: expected 8 bytes, got #{bytes_length} bytes"
        sport, dport, length, checksum = bytes.unpack(FMT_nnnn)
        bytes_length >= length or 
            raise ParseError, "Truncated UDP packet: expected #{length} bytes, got #{bytes_length} bytes"
        udp = UDP.new sport, dport
        udp.payload_raw = bytes[8..-1]
        udp.payload = bytes[8..length]
        return udp
    end

    def write io, ip
        length = @payload.length
        length_8 = length + 8
        if length_8 > 65535
            Pcap.warning "UDP payload is too large"
        end
        pseudo_header = ip.pseudo_header length_8
        header = [@src_port, @dst_port, length_8, 0] \
            .pack FMT_nnnn
        checksum = IP.checksum(pseudo_header + header + @payload)
        header = [@src_port, @dst_port, length_8, checksum] \
            .pack FMT_nnnn
        io.write header
        io.write @payload
    end

    def self.udp? packet
        return packet.is_a?(Ethernet) &&
            packet.payload.is_a?(IP) &&
            packet.payload.payload.is_a?(UDP)
    end

    def to_s
        return "udp(%d, %d, %s)" % [@src_port, @dst_port, @payload.inspect]
    end

    def == other
        return super &&
            self.src_port == other.src_port &&
            self.dst_port == other.dst_port
    end
end

end
end
