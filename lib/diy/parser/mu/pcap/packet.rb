# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class Packet
    attr_accessor :payload, :payload_raw

    def initialize
        @payload = ''
        @payload_raw = ''
    end

    # Get payload as bytes.  If the payload is a parsed object, returns
    # raw payload.  Otherwise return unparsed bytes.
    def payload_bytes
        if @payload.is_a? String
            return @payload
        end
        return @payload_raw
    end

    def deepdup
        dup = self.dup
        if @payload.respond_to? :deepdup
            dup.payload = @payload.deepdup
        else
            dup.payload = @payload.dup
        end
        return dup
    end

    def flow_id
        raise NotImplementedError
    end

    # Reassemble, reorder, and merge packets.
    def self.normalize packets
        begin
            packets = TCP.reorder packets
        rescue TCP::ReorderError => e
            Pcap.warning e
        end

        begin
            packets = SCTP.reorder packets
        rescue SCTP::ReorderError => e
            Pcap.warning e
        end

        begin
            packets = TCP.merge packets
        rescue TCP::MergeError => e
            Pcap.warning e
        end
        return packets
    end

    # Remove non-L7/DNS/DHCP traffic if there is L7 traffic.  Returns
    # original packets if there is no L7 traffic.
    IGNORE_UDP_PORTS = [
        53,      # DNS
        67, 68,  # DHCP
        546, 547 # DHCPv6
    ]
    def self.isolate_l7 packets
        cleaned_packets = []
        packets.each do |packet|
            if TCP.tcp? packet
                cleaned_packets << packet
            elsif UDP.udp? packet
                src_port = packet.payload.payload.src_port
                dst_port = packet.payload.payload.dst_port
                if not IGNORE_UDP_PORTS.member? src_port and
                    not IGNORE_UDP_PORTS.member? dst_port
                    cleaned_packets << packet
                end
            elsif SCTP.sctp? packet
                cleaned_packets << packet
            end
        end
        if cleaned_packets.empty?
            return packets
        end
        return cleaned_packets
    end

    def to_bytes
        io = StringIO.new
        write io
        io.close
        return io.string
    end

    def == other
        return self.class == other.class && self.payload == other.payload &&
            self.payload_raw == other.payload_raw
    end
end

end
end
