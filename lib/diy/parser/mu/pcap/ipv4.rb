# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'ipaddr'

module Mu
class Pcap

class IPv4 < IP
    IP_RF = 0x8000 # Reserved
    IP_DF = 0x4000 # Don't fragment
    IP_MF = 0x2000 # More fragments
    IP_OFFMASK = 0x1fff

    FMT_HEADER = 'CCnnnCCna4a4'

    attr_accessor :ip_id, :offset, :ttl, :proto, :src, :dst, :dscp

    def initialize src=nil, dst=nil, ip_id=0, offset=0, ttl=64, proto=0, dscp=0
        super()
        @ip_id  = ip_id
        @offset = offset
        @ttl    = ttl
        @proto  = proto
        @src    = src
        @dst    = dst
        @dscp   = dscp
    end

    def v4?
        return true
    end

    def flow_id
        if not @payload or @payload.is_a? String
            return [:ipv4, @proto, @src, @dst]
        else
            return [:ipv4, @src, @dst, @payload.flow_id]
        end
    end

    NTOP = {} # Network to human cache
    HTON = {} # Human to network cache

    def self.from_bytes bytes
        bytes.length >= 20 or
            raise ParseError, "Truncated IPv4 header: expected at least 20 bytes, got #{bytes.length} bytes"

        vhl, tos, length, id, offset, ttl, proto, checksum, src, dst = bytes[0,20].unpack FMT_HEADER
        version = vhl >> 4 
        hl = (vhl & 0b1111) * 4

        version == 4 or
            raise ParseError, "Wrong IPv4 version: got (#{version})"
        hl >= 20 or
            raise ParseError, "Bad IPv4 header length: expected at least 20 bytes raise ParseError, got #{hl} bytes"
        bytes.length >= hl or
            raise ParseError, "Truncated IPv4 header: expected #{hl} bytes raise ParseError, got #{bytes.length} bytes"
        length >= 20 or
            raise ParseError, "Bad IPv4 packet length: expected at least 20 bytes raise ParseError, got #{length} bytes"
        bytes.length >= length or
            raise ParseError, "Truncated IPv4 packet: expected #{length} bytes raise ParseError, got #{bytes.length} bytes"

        if hl != 20
            IPv4.check_options bytes[20, hl-20]
        end

        src = NTOP[src] ||= IPAddr.ntop(src)
        dst = NTOP[dst] ||= IPAddr.ntop(dst)
        dscp = tos >> 2
        ipv4 = IPv4.new(src, dst, id, offset, ttl, proto, dscp)
        ipv4.payload_raw = bytes[hl..-1]

        payload = bytes[hl...length]
        if offset & (IP_OFFMASK | IP_MF) == 0
            begin
                case proto
                when IPPROTO_TCP
                    ipv4.payload = TCP.from_bytes payload
                when IPPROTO_UDP
                    ipv4.payload = UDP.from_bytes payload
                when IPPROTO_SCTP
                    ipv4.payload = SCTP.from_bytes payload
                else
                    ipv4.payload = payload
                end
            rescue ParseError => e
                Pcap.warning e
            end
        else
            ipv4.payload = payload
        end
        return ipv4
    end

    def write io
        if @payload.is_a? String
            payload = @payload
        else
            string_io = StringIO.new
            @payload.write string_io, self
            payload = string_io.string
        end
        length = 20 + payload.length
        if length > 65535
            Pcap.warning "IPv4 payload is too large"
        end

        src = HTON[@src] ||= IPAddr.new(@src).hton
        dst = HTON[@dst] ||= IPAddr.new(@dst).hton
        fields = [0x45, @dscp << 2, length, @ip_id, @offset, @ttl, @proto, 0, src, dst] 
        header = fields.pack(FMT_HEADER)
        fields[7] = IP.checksum(header)
        header = fields.pack(FMT_HEADER)
        io.write header
        io.write payload
    end

    FMT_PSEUDO_HEADER = 'a4a4CCn'
    def pseudo_header payload_length
        src = HTON[@src] ||= IPAddr.new(@src).hton
        dst = HTON[@dst] ||= IPAddr.new(@dst).hton
        return [src, dst, 0, @proto, payload_length].pack(FMT_PSEUDO_HEADER)
    end

    def fragment?
        return (@offset & (IP_OFFMASK | IP_MF) != 0)
    end

    # Check that IP or TCP options are valid.  Do nothing if they are valid.
    # Both IP and TCP options are 8-bit TLVs with an inclusive length.  Both
    # have one byte options 0 and 1.
    def self.check_options options, label='IPv4'
        while not options.empty?
            type = options.slice!(0, 1)[0].ord
            if type == 0 or type == 1
                next
            end
            Pcap.assert !options.empty?,
                "#{label} option #{type} is missing the length field"
            length = options.slice!(0, 1)[0].ord
            Pcap.assert length >= 2,
                "#{label} option #{type} has invalid length: #{length}"
            Pcap.assert length - 2 <= options.length,
                "#{label} option #{type} has truncated data"
            options.slice! 0, length - 2
        end
    end

    ReassembleState = ::Struct.new :packets, :bytes, :mf, :overlap

    # Reassemble fragmented IPv4 packets
    def self.reassemble packets
        reassembled_packets = []
        flow_id_to_state = {}
        packets.each do |packet|
            if not packet.is_a?(Ethernet) or not packet.payload.is_a?(IPv4)
                # Ignore non-IPv4 packet
            elsif not packet.payload.fragment?
                # Ignore non-fragments
            else
                # Get reassembly state
                ip = packet.payload
                flow_id = [ip.ip_id, ip.proto, ip.src, ip.dst]
                state = flow_id_to_state[flow_id]
                if not state
                    state = ReassembleState.new [], [], true, false
                    flow_id_to_state[flow_id] = state
                end
                state.packets << packet

                # Clear the more-fragments flag if no more fragments
                if ip.offset & IP_MF == 0
                    state.mf = false
                end

                # Add the bytes
                start = (ip.offset & IP_OFFMASK) * 8
                finish = start + ip.payload.length
                state.bytes.fill nil, start, finish - start
                start.upto(finish-1) do |i|
                    if not state.bytes[i]
                        byte = ip.payload[i - start].chr
                        state.bytes[i] = byte
                    elsif not state.overlap
                        name = "%s:%s:%d" % [ip.src, ip.dst, ip.proto]
                        Pcap.warning \
                            "IPv4 flow #{name} contains overlapping fragements"
                        state.overlap = true
                    end
                end

                # We're done if we've received a fragment without the
                # more-fragments flag and all the bytes in the buffer have been
                # set.
                if not state.mf and state.bytes.all?
                    # Remove fragments from reassembled_packets
                    state.packets.each do |packet|
                        reassembled_packets.delete_if do |reassembled_packet|
                            packet.object_id == reassembled_packet.object_id
                        end
                    end
                    # Remove state
                    flow_id_to_state.delete flow_id
                    # Create new packet
                    packet = state.packets[0].deepdup
                    ipv4 = packet.payload
                    ipv4.offset = 0
                    ipv4.payload = state.bytes.join
                    # Decode
                    begin
                        case ipv4.proto
                        when IPPROTO_TCP
                            ipv4.payload = TCP.from_bytes ipv4.payload
                        when IPPROTO_UDP
                            ipv4.payload = UDP.from_bytes ipv4.payload
                        when IPPROTO_SCTP
                            ipv4.payload = SCTP.from_bytes ipv4.payload
                        end
                    rescue ParseError => e
                        Pcap.warning e
                    end
                end
            end
            reassembled_packets << packet
        end
        if !flow_id_to_state.empty?
            Pcap.warning \
                "#{flow_id_to_state.length} flow(s) have IPv4 fragments " \
                "that can't be reassembled"
        end

        return reassembled_packets
    end

    def to_s
        if @payload.is_a? String
            payload = @payload.inspect
        else
            payload = @payload.to_s
        end
        return "ipv4(%d, %s, %s, %s)" % [@proto, @src, @dst, payload]
    end

    def == other
        return super &&
            self.proto  == other.proto &&
            self.ip_id  == other.ip_id &&
            self.offset == other.offset &&
            self.ttl    == other.ttl &&
            self.dscp   == other.dscp
    end
end

end
end
