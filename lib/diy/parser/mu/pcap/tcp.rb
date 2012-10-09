# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'mu/pcap/reader'
require 'mu/pcap/stream_packetizer'

module Mu
class Pcap

class TCP < Packet
    attr_accessor :src_port, :dst_port, :seq, :ack, :flags, :window, :urgent, :mss, :proto_family

    TH_FIN  = 0x01
    TH_SYN  = 0x02
    TH_RST  = 0x04
    TH_PUSH = 0x08
    TH_ACK  = 0x10
    TH_URG  = 0x20
    TH_ECE  = 0x40
    TH_CWR  = 0x80

    MSS     = 2

    def initialize
        super
        @src_port = 0
        @dst_port = 0
        @seq = 0
        @ack = 0
        @flags = 0
        @window = 0
        @urgent = 0
        @mss = 0
        @proto_family = nil
    end

    def flow_id
        return [:tcp, @src_port, @dst_port]
    end

    def self.from_bytes bytes
        Pcap.assert bytes.length >= 20, 'Truncated TCP header: ' +
            "expected 20 bytes, got #{bytes.length} bytes"
        sport, dport, seq, ack, offset, flags, win, sum, urp = 
            bytes.unpack('nnNNCCnnn')
        offset = (offset >> 4) * 4
        Pcap.assert offset >= 20, 'Truncated TCP header: ' +
               "expected at least 20 bytes, got #{offset} bytes"
        Pcap.assert bytes.length >= offset, 'Truncated TCP header: ' +
            "expected at least #{offset} bytes, got #{bytes.length} bytes"

        if TH_SYN == flags
            ss = TCP.get_option bytes[20, offset-20], MSS
        else
            ss = 0
        end

        IPv4.check_options bytes[20, offset-20], 'TCP'

        tcp = TCP.new
        tcp.src_port = sport
        tcp.dst_port = dport
        tcp.seq      = seq
        tcp.ack      = ack
        tcp.flags    = flags
        tcp.window   = win
        tcp.urgent   = urp
        tcp.mss      = ss
        tcp.payload = tcp.payload_raw = bytes[offset..-1]
        return tcp
    end

    def self.get_option options, option_type
        while not options.empty?
            type = options.slice!(0, 1)[0].ord
            if type == 0 or type == 1
                next
            end
            length = options.slice!(0, 1)[0].ord
            if 2 < length
                case length
                    when 3
                        format = "C"
                    when 4
                        format = "n"
                    when 6
                        format = "N"
                    when 10
                        format = "Q"
                    else
                        Pcap.warning "Bad TCP option length: #{length}"
                end
                option = options.slice!(0, length - 2).unpack(format)[0]
            end
            if option_type == type
                return option
            end
        end
        return 0
    end

    def write io, ip
        if @payload.length + 40 > 65535
            raise NotImplementedError, "TCP segment too large"
        end
        pseudo_header = ip.pseudo_header 20 + @payload.length
        header = [@src_port, @dst_port, @seq, @ack, 5 << 4, @flags, @window, 
                  0, @urgent].pack('nnNNCCnnn')
        checksum = IP.checksum pseudo_header + header + @payload
        header = [@src_port, @dst_port, @seq, @ack, 5 << 4, @flags, @window, 
                  checksum, @urgent].pack('nnNNCCnnn')
        io.write header
        io.write @payload
    end

    class ReorderError < StandardError ; end

    ReorderState = ::Struct.new(:next_seq, :queued)

    # Reorder packets by TCP sequence number.  TCP packets are assumed to
    # be over IP over Ethernet.
    def self.reorder packets
        packets = packets.dup
        reordered_packets = []
        flow_to_state = {}
        while not packets.empty?
            packet = packets.shift
            # Don't reorder non-TCP packets
            if not tcp? packet
                reordered_packets << packet
                next
            end
            # Sanity check: must not be a fragment
            if packet.payload.v4? and packet.payload.fragment?
                raise ReorderError, "TCP stream contains IP fragments"
            end
            tcp = packet.payload.payload
            # Must not contain urgent data
            if tcp.flags & TH_URG != 0
                raise ReorderError, "TCP stream contains urgent data: "+
                    pretty_flow_name(packet)
            end
            # Get/create state
            if flow_to_state.member? packet.flow_id
                state = flow_to_state[packet.flow_id]
            else
                state = ReorderState.new nil, []
                flow_to_state[packet.flow_id] = state
            end
            if not state.next_seq
                # First packet in TCP stream
                reordered_packets << packet
                state.next_seq = tcp.seq + tcp.payload.length
                if tcp.flags & TCP::TH_SYN != 0
                    state.next_seq += 1
                end
                if tcp.flags & TCP::TH_FIN != 0
                    state.next_seq += 1
                end
                state.next_seq %= 2**32
            elsif seq_eq(tcp.seq, state.next_seq)
                # Next expected sequence number in TCP stream

                # SYN must not appear in middle of stream
                if tcp.flags & TCP::TH_SYN != 0
                    raise ReorderError, "SYN in middle of TCP stream " +
                        pretty_flow_name(packet)
                end

                reordered_packets << packet
                state.next_seq += tcp.payload.length
                if tcp.flags & TCP::TH_FIN != 0
                    state.next_seq += 1
                end
                state.next_seq %= 2**32

                # Reinject any packets in the queue into the packet stream
                if not state.queued.empty?
                    packets.unshift(*state.queued)
                    state.queued.clear
                end
            elsif seq_lt(tcp.seq, state.next_seq)
                # Old sequence number
                if seq_lte(tcp.seq + tcp.payload.length, state.next_seq)
                    # No overlap: retransmitted packet, ignore
                else
                    # Overlap: reassembler must slice in overlapping data
                    reordered_packets << packet
                end
            else
                # Future sequence number - queue
                state.queued << packet
            end
        end

        flow_to_state.each do |flow_id, state|
            if not state.queued.empty?
                raise ReorderError, "Data missing from TCP stream "+
                    pretty_flow_name(state.queued[0]) + ': ' +
                    "expecting sequence number #{state.next_seq}"
            end
        end

        return reordered_packets
    end

    class MergeError < StandardError ; end

    # Merge adjacent TCP packets.  Non-data TCP packets are also removed.
    # reorder() should be run first.  This can create packets that are larger
    # than the maximum possible IPv4 packet - use split() to make them smaller.
    def self.merge packets
        merged_packets = []
        merged_packet = nil
        next_seq = nil
        packets.each do |packet|
            if not tcp? packet
                # Skip non-TCP packets.
                if merged_packet
                    merged_packets << merged_packet
                    merged_packet = nil
                end
                merged_packets << packet
            elsif packet.payload.v4? and packet.payload.fragment?
                # Sanity check: must not be a fragment
                raise MergeError, 'TCP stream contains IP fragments'
            else
                tcp = packet.payload.payload
                if tcp.flags & TCP::TH_SYN == 0 and tcp.payload == ''
                    # Ignore non-data packets.  SYNs are kept so the TCP
                    # transport is created at the correct spot.
                elsif not merged_packet or 
                    merged_packet.flow_id != packet.flow_id
                    # New TCP stream
                    if merged_packet
                        merged_packets << merged_packet
                    end
                    merged_packet = packet.deepdup
                    next_seq = tcp.seq + tcp.payload.length
                elsif seq_eq tcp.seq, next_seq
                    # Next expected sequence number
                    merged_packet.payload.payload.payload << tcp.payload
                    next_seq += tcp.payload.length
                elsif seq_lte(tcp.seq + tcp.payload.length, next_seq)
                    # Old data: ignore
                elsif seq_lt tcp.seq, next_seq
                    # Overlapping segment: merge newest part
                    length = seq_sub(tcp.seq + tcp.payload.length, next_seq)
                    bytes = tcp.payload[-length..-1]
                    merged_packet.payload.payload.payload << bytes
                    next_seq += length
                else
                    # Error (sanify check, reorder_tcp will raise an error)
                    raise MergeError, 'TCP stream is missing segments'
                end
                if next_seq
                    if tcp.flags & TCP::TH_SYN != 0
                        next_seq += 1
                    end
                    if tcp.flags & TCP::TH_FIN != 0
                        next_seq += 1
                    end
                    next_seq %= 2**32
                end
            end
        end
        if merged_packet
            merged_packets << merged_packet
        end

        merged_packets = create_message_boundaries(merged_packets)

        return merged_packets
    end

    def self.create_message_boundaries packets
        # Get complete bytes for each tcp flow before trying to 
        # identify the protocol.
        flow_to_bytes = {}
        packets.each do |packet|
            if tcp? packet
                tcp = packet.payload.payload
                flow = packet.flow_id
                bytes = flow_to_bytes[flow] ||= ""
                bytes << tcp.payload.to_s
            end
        end

        # If any proto plugin can parse a message off of the stream we will
        # use that plugin to detect message boundaries and guide message
        # reassembly.
        flow_to_packetizer = {}
        flow_to_bytes.each_pair do |flow, bytes|
            [ Reader::HttpFamily ].each do |klass|
                reader = klass.new
                reader.pcap2scenario = true
                if reader.read_message bytes
                    tx_key = flow.flatten.sort_by {|o| o.to_s}

                    tx = flow_to_packetizer[tx_key] ||= StreamPacketizer.new(klass.new)
                    break
                end
            end
        end

        # Merge/split packets along message boundaries. This is done as an 
        # atomic transaction per tcp connection. The loop below adds merged
        # packets alongside the original unmerged packets. If the stream
        # is completely merged (no fragments left at end) we remove the
        # original packets otherwise we rollback by removing the newly
        # created packets.
        changes = Hash.new do |hash,key|
            # tuple of original/replacement packets per flow.
            hash[key] = [[], []]
        end
        rollback_list = []

        merged = []
        partial_messages = Hash.new {|hash,key| hash[key] = []}
        packets.each do |packet|
            merged << packet

            next if not tcp? packet
            tcp = packet.payload.payload

            flow = packet.flow_id

            # Check if we have message boundaries for this flow
            tx_key = flow.flatten.sort_by {|o| o.to_s}
            if not tx = flow_to_packetizer[tx_key]
                next
            end

            # Keep track of new vs orig packets so we can delete one set at the end.
            orig_packets, new_packets = changes[flow]
            orig_packets << packet

            if tcp.payload.empty?
                p = packet.deepdup
                new_packets << p
                p.payload.payload.proto_family = tx.parser.family
                next
            end

            # Does the current packet result in any completed messages?
            tx.push(flow, tcp.payload)
            fragments = partial_messages[flow]
            if tx.msg_count(flow) == 0
                # No, record packet as a fragment and move to next packet.
                fragments << packet
                next
            end

            # Yes, packet did result in completed messages. Create a new
            # tcp packet for each higher level protocol message.
            first_inc_packet = (fragments.empty? ? packet : fragments[0])
            next_seq = first_inc_packet.payload.payload.seq
            while tcp_payload = tx.next_msg(flow)
                if tcp_payload.size > MAX_SEGMENT_PAYLOAD
                    # Abort merging for this flow because this packet
                    # will be split and result in a scenario where
                    # we send one logical message but try and receive
                    # two.
                    rollback_list << tx_key 
                    $stderr.puts "Warning: Message too big, cannot enforce " \
                                 "message boundaries."
                end
                next_packet = packet.deepdup
                new_packets << next_packet
                next_tcp = next_packet.payload.payload
                next_tcp.seq = next_seq
                next_tcp.payload = tcp_payload
                next_tcp.proto_family = tx.parser.family
                next_seq += tcp_payload.size
                merged << next_packet
            end
            fragments.clear

            # If there are unconsumed bytes then add a fragment to the
            # incomplete list.
            if extra_bytes = tx.extra_bytes(flow)
                frag = packet.deepdup
                new_packets << frag
                fragments << frag
                tcp = frag.payload.payload
                tcp.payload = extra_bytes
                tcp.seq     = next_seq
                tcp.proto_family = tx.parser.family
            end
        end

        # Figure out which connections have incompletely merged flows.
        # Rollback for those and commit the rest.
        partial_messages.each_pair do |flow, list|
            if not list.empty?
                tx_key = flow.flatten.sort_by {|o| o.to_s}
                $stderr.puts "Warning: Left over fragments, cannot force message boundaries."
                rollback_list << tx_key
            end
        end
        changes.each_pair do |flow, orig_new|
            orig, new = orig_new
            tx_key = flow.flatten.sort_by {|o| o.to_s}
            if rollback_list.include?(tx_key)
                new.each {|p| p.payload = :remove}
            else
                orig.each {|p| p.payload = :remove}
            end
        end
        merged.reject! {|p| p.payload == :remove}

        merged
    end


    # Split-up TCP packets that are too large to serialize.  (I.e., total
    # length including all headers greater than 65535 - 20 - 20 - 14.)
    MAX_SEGMENT_PAYLOAD = 65535 - 20 - 20 - 14
    def self.split packets
        split_packets = []
        packets.each do |packet|
            if not tcp? packet
                # Skip non-TCP packets.
                split_packets << packet
                next
            elsif packet.payload.v4? and packet.payload.fragment?
                # Sanity check: must not be a fragment
                raise MergeError, 'TCP stream contains IP fragments'
            elsif packet.payload.payload.payload.length <= MAX_SEGMENT_PAYLOAD
                split_packets << packet
            else
                tcp = packet.payload.payload
                payload = tcp.payload
                tcp.payload = payload.slice! 0, MAX_SEGMENT_PAYLOAD
                next_seq = tcp.seq + tcp.payload.length
                split_packets << packet
                while payload != ''
                    next_packet = packet.deepdup
                    next_tcp = next_packet.payload.payload
                    next_tcp.seq = next_seq
                    next_tcp.payload = payload.slice! 0, MAX_SEGMENT_PAYLOAD
                    next_seq += next_tcp.payload.length
                    split_packets << next_packet
                end
            end
        end
        return split_packets
    end

    def self.tcp? packet
        return packet.is_a?(Ethernet) &&
            packet.payload.is_a?(IP) &&
            packet.payload.payload.is_a?(TCP)
    end

    # Subtract two sequence numbers module 2**32.
    def self.seq_sub a, b
        if a - b > 2**31
            return -((b - a) % 2**32)
        elsif a - b < -2**31
            return (a - b) % 2**32
        else
            return a - b
        end
    end

    # Compare TCP sequence numbers modulo 2**32.
    def self.seq_eq a, b
        return seq_sub(a, b) == 0
    end

    def self.seq_lt a, b
        return seq_sub(a, b) < 0
    end

    def self.seq_lte a, b
        return seq_sub(a, b) <= 0
    end

    # Generate a pretty name for a TCP flow
    def self.pretty_flow_name packet
        ip = packet.payload
        return "#{ip.src}:#{ip.payload.src_port} <-> " +
            "#{ip.dst}:#{ip.payload.dst_port}"
    end

    def to_s
        return "tcp(%d, %d, %s)" % [@src_port, @dst_port, @payload.inspect]
    end

    def == other
        return super &&
            self.src_port == other.src_port &&
            self.dst_port == other.dst_port &&
            self.seq      == other.seq &&
            self.ack      == other.ack &&
            self.flags    == other.flags &&
            self.window   == other.window &&
            self.urgent   == other.urgent
    end
end

end
end
