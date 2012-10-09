# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Scenario
module Pcap
module Rtp

    TRUNC_COUNT = 5

    def self.preprocess packets, fields_per_packet
        signaled_by = []
        prev_signal_frame = {}
        packets.each_with_index do |packet, idx|
            fields = fields_per_packet[idx]
            if fields and fields[:rtp]
                flow_id = packet.flow_id
                if frame = fields[:"rtp.setup-frame"]
                    prev_signal_frame[flow_id] = frame
                else
                    if frame = prev_signal_frame[flow_id]
                        fields[:"rtp.setup-frame"] = frame
                    else
                        packets[idx] = nil
                        fields_per_packet[idx] = nil
                        next
                   end
                end
                sig_idx = frame.to_i 
                signaled_by[idx] = sig_idx
            end
        end

        flow_to_count = Hash.new 0
        prev_setup_frame = {} 
        keep_frames = []
        packets.each_with_index do |packet, idx|
            if setup_frame = signaled_by[idx]
                flow = packet.flow_id
                count = flow_to_count[flow]
                if setup_frame != prev_setup_frame[flow]
                    prev_setup_frame[flow] = setup_frame
                    count = 1
                else
                    count += 1 
                end
                if count <= TRUNC_COUNT
                    keep_frames << idx + 1
                else
                    packets[idx] = nil
                    fields_per_packet[idx] = nil
                end
                flow_to_count[flow] = count
            end
        end

        packets.reject! {|p| not p }
        fields_per_packet.reject! {|p| not p }

        filter = "not rtp"
        keep_frames.each do |frame|
            filter << " or frame.number == #{frame}"
        end

        return filter
    end
end
end
end
end
