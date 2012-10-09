# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'ipaddr'

module Mu
class Pcap

class IPv6 < IP
    FORMAT = 'NnCCa16a16'

    attr_accessor :next_header, :hop_limit

    def initialize
        super
        @next_header = 0
        @hop_limit   = 64
    end

    def v6?
        return true
    end

    alias :proto :next_header
    alias :ttl   :hop_limit

    def flow_id
        if not @payload or @payload.is_a? String
            return [:ipv6, @next_header, @src, @dst]
        else
            return [:ipv6, @src, @dst, @payload.flow_id]
        end
    end

    def self.from_bytes bytes
        Pcap.assert bytes.length >= 40, 'Truncated IPv6 header: ' +
            "expected at least 40 bytes, got #{bytes.length} bytes"

        vcl, length, next_header, hop_limit, src, dst = 
            bytes[0, 40].unpack FORMAT
        version = vcl >> 28 & 0x0f
        traffic_class = vcl >> 20 & 0xff
        flow_label = vcl & 0xfffff

        Pcap.assert version == 6, "Wrong IPv6 version: got (#{version})"
        Pcap.assert bytes.length >= (40 + length), 'Truncated IPv6 header: ' +
            "expected #{length + 40} bytes, got #{bytes.length} bytes"

        ipv6 = IPv6.new
        ipv6.next_header = next_header
        ipv6.hop_limit = hop_limit
        ipv6.src = IPAddr.new_ntoh(src).to_s
        ipv6.dst = IPAddr.new_ntoh(dst).to_s

        ipv6.payload_raw = bytes[40..-1]
        ipv6.next_header, ipv6.payload =
            payload_from_bytes ipv6, ipv6.next_header, bytes[40...40+length]

        return ipv6
    end

    # Parse bytes and returns next_header and payload.  Skips extension
    # headers.
    def self.payload_from_bytes ipv6, next_header, bytes
        begin
            case next_header
            when IPPROTO_TCP
                payload = TCP.from_bytes bytes
            when IPPROTO_UDP
                payload = UDP.from_bytes bytes
            when IPPROTO_SCTP
                payload = SCTP.from_bytes bytes
            when IPPROTO_HOPOPTS
                next_header, payload = eight_byte_header_from_bytes(ipv6,
                    bytes, 'hop-by-hop options')
            when IPPROTO_ROUTING
                next_header, payload = eight_byte_header_from_bytes(ipv6,
                    bytes, 'routing')
            when IPPROTO_DSTOPTS
                next_header, payload = eight_byte_header_from_bytes(ipv6,
                    bytes, 'destination options')
            when IPPROTO_FRAGMENT
                Pcap.assert bytes.length >= 8,
                    "Truncated IPv6 fragment header"
                Pcap.assert false, 'IPv6 fragments are not supported'
            when IPPROTO_AH
                next_header, payload = ah_header_from_bytes(ipv6,
                    bytes, 'authentication header')
            when IPPROTO_NONE
                payload = ''
            else
                payload = bytes
            end
        rescue ParseError => e
            Pcap.warning e
            payload = bytes
        end
        return [next_header, payload]
    end

    # Parse extension header that's a multiple of 8 bytes
    def self.eight_byte_header_from_bytes ipv6, bytes, name
        Pcap.assert bytes.length >= 8, "Truncated IPv6 #{name} header"
        length = (bytes[1].ord + 1) * 8
        Pcap.assert bytes.length >= length, "Truncated IPv6 #{name} header"
        return payload_from_bytes(ipv6, bytes[0].ord, bytes[length..-1])
    end

    # Parse authentication header (whose length field is interpeted differently)
    def self.ah_header_from_bytes ipv6, bytes, name
        Pcap.assert bytes.length >= 8, "Truncated IPv6 #{name} header"
        length = (bytes[1].ord + 2) * 4
        Pcap.assert bytes.length >= length, "Truncated IPv6 #{name} header"
        return payload_from_bytes(ipv6, bytes[0].ord, bytes[length..-1])
    end

    def write io
        if @payload.is_a? String
            payload = @payload
        else
            string_io = StringIO.new
            @payload.write string_io, self
            payload = string_io.string
        end
        src = IPAddr.new(@src, Socket::AF_INET6).hton
        dst = IPAddr.new(@dst, Socket::AF_INET6).hton
        header = [0x60000000, payload.length, @next_header, @hop_limit, 
                  src, dst].pack FORMAT
        io.write header
        io.write payload
    end

    def pseudo_header payload_length
        return IPAddr.new(@src, Socket::AF_INET6).hton +
            IPAddr.new(@dst, Socket::AF_INET6).hton +
            [payload_length, '', @next_header].pack('Na3C')
    end

    def == other
        return super &&
            self.next_header == other.next_header &&
            self.hop_limit   == other.hop_limit
    end
end

end
end
