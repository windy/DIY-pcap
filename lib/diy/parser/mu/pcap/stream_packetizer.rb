# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'mu/pcap/io_pair'
require 'mu/pcap/io_wrapper'

module Mu
class Pcap
class StreamPacketizer
    attr_reader :io_pair, :parser
    def initialize parser
        @parser = parser
        @key_to_idx = Hash.new do |hash,key|
            if hash.size >= 2
                raise ArgumentError, "Only two endpoints are allowed in a transaction"
            end
            hash[key] = hash.size
        end
        @sent_messages = [[], []].freeze
        @inner_pair = IOPair.stream_pair
        @io_pair = @inner_pair.map{|io| IOWrapper.new io, parser}.freeze
    end

    def msg_count key
        key = key.inspect
        widx       = @key_to_idx[key]
        messages = @sent_messages[widx]
        messages.size
    end

    def extra_bytes w_key
        w_key = w_key.inspect

        ridx       = @key_to_idx[w_key] ^ 1
        reader = @io_pair[ridx]
        incomplete =  reader.unread
        incomplete.empty? ? nil : incomplete.dup
    end

    def push key, bytes
        key = key.inspect
        widx       = @key_to_idx[key]
        writer     = @io_pair[widx]
        raw_writer = @inner_pair[widx]
        raw_writer.write bytes

        messages = @sent_messages[widx]

        ridx = widx ^ 1
        reader = @io_pair[ridx]
        while msg = reader.read
            messages << msg
            writer.record_write bytes
        end

        nil
    end

    def next_msg key
        key = key.inspect
        idx = @key_to_idx[key] 
        if m = @sent_messages[idx].shift
            return m.dup
        else
            nil
        end
    end
end
end
end

