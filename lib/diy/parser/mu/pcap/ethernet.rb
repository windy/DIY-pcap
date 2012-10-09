# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class Ethernet < Packet
    attr_accessor :src, :dst, :type
    
    ETHERTYPE_IP  = 0x0800
    ETHERTYPE_IP6 = 0x86dd
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_PPPOE_SESSION = 0x8864
    ETHERTYPE_802_1Q = 0X8100

    PPP_IP   = 0x0021
    PPP_IPV6 = 0x0057 

    def initialize src=nil, dst=nil, type=0
        super()
        @src = src
        @dst = dst
        @type = type
    end

    def flow_id
        if not @payload or @payload.is_a? String
            return [:ethernet, @src, @dst, @type]
        else
            return @payload.flow_id
        end
    end

    FMT_MAC = "C6"
    FMT_n = 'n'
    MAC_TEMPLATE = '%02x:%02x:%02x:%02x:%02x:%02x'
    def self.from_bytes bytes
        if bytes.length < 14
            raise ParseError, "Truncated Ethernet header: expected 14 bytes, got #{bytes.length} bytes"
        end

        dst = bytes.slice!(0,6).unpack FMT_MAC
        dst = MAC_TEMPLATE % dst
        src = bytes.slice!(0,6).unpack FMT_MAC
        src = MAC_TEMPLATE % src
        type = bytes.slice!(0,2).unpack(FMT_n)[0]
        while (type == ETHERTYPE_802_1Q)
            # Skip 4 bytes for 802.1q vlan tag field
            bytes.slice!(0,2)
            type = bytes.slice!(0,2).unpack(FMT_n)[0]
        end
        ethernet = Ethernet.new src, dst, type
        ethernet.payload = bytes
        ethernet.payload_raw = bytes
        begin
            case type
            when ETHERTYPE_IP
                ethernet.payload = IPv4.from_bytes bytes
            when ETHERTYPE_IP6
                ethernet.payload = IPv6.from_bytes bytes
            when ETHERTYPE_PPPOE_SESSION
                # Remove PPPoE/PPP session layer
                ethernet.payload = bytes
                ethernet.remove_pppoe!
            else
                ethernet.payload = bytes
            end
        rescue ParseError => e
            Pcap.warning e
        end
        return ethernet
    end

    def ip?
        return payload.is_a?(IP)
    end
    
    ADDR_TO_BYTES = {}
    FMT_HEADER = 'a6a6n'
    def write io
        dst_mac = ADDR_TO_BYTES[@dst] ||= @dst.split(':').inject('') {|m, b| m << b.to_i(16).chr}
        src_mac = ADDR_TO_BYTES[@src] ||= @src.split(':').inject('') {|m, b| m << b.to_i(16).chr}
        bytes = [dst_mac, src_mac, @type].pack(FMT_HEADER)
        io.write bytes
        if @payload.is_a? String
            io.write @payload
        else
            @payload.write io
        end
    end

    # Remove the PPPoE and PPP headers.  PPPoE is documented in RFC 2516.
    def remove_pppoe!
        bytes = self.payload_raw

        # Remove PPPoE header
        Pcap.assert bytes.length >= 6, 'Truncated PPPoE header: ' +
            "expected at least 6 bytes, got #{bytes.length} bytes"
        version_type, code, session_id, length = bytes.unpack 'CCnn'
        version = version_type >> 4 & 0b1111
        type    = version_type      & 0b1111
        Pcap.assert version == 1, "Unknown PPPoE version: #{version}"
        Pcap.assert type == 1, "Unknown PPPoE type: #{type}"
        Pcap.assert code == 0, "Unknown PPPoE code: #{code}"
        bytes = bytes[6..-1]
        Pcap.assert bytes.length >= length, 'Truncated PPoE packet: ' +
            "expected #{length} bytes, got #{bytes.length} bytes"
        
        # Remove PPP header
        Pcap.assert bytes.length >= 2, 'Truncated PPP packet: ' +
            "expected at least bytes, got #{bytes.length} bytes"
        protocol_id, = bytes.unpack 'n'
        bytes = bytes[2..-1]
        case protocol_id
        when PPP_IP
            self.payload = IPv4.from_bytes bytes
            self.payload_raw = bytes
            self.type = ETHERTYPE_IP
        when PPP_IPV6
            self.payload = IPv6.from_bytes bytes
            self.payload_raw = bytes
            self.type = ETHERTYPE_IP6
        else
            # Failed.  Don't update payload or type.
            raise ParseError, "Unknown PPP protocol: 0x#{'%04x' % protocol_id}"
        end
    end

    def to_s
        if @payload.is_a? String
            payload = @payload.inspect
        else
            payload = @payload.to_s
        end
        return "ethernet(%s, %s, %d, %s)" % [@src, @dst, @type, payload]
    end

    def == other
        return super &&
            self.src  == other.src &&
            self.dst  == other.dst &&
            self.type == other.type
    end
end

end
end
