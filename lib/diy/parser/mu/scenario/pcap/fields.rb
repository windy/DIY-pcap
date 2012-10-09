# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'mu/scenario/pcap'

module Mu
class Scenario
module Pcap

class Fields
    FIELDS = [
        :rtp,
        :"rtp.setup-frame"
    ].freeze
    FIELD_COUNT = FIELDS.length
    SEPARATOR   = "\xff".freeze
    TSHARK_OPTS = "-Eseparator='#{SEPARATOR}'" 
    FIELDS.each do |field|
        TSHARK_OPTS << " -e #{field}"
    end
    TSHARK_OPTS.freeze

    def self.readline io
        if ::IO.select [ io ], nil, nil, Pcap::TSHARK_READ_TIMEOUT
            return io.readline.chomp
        end 
        
        raise Errno::ETIMEDOUT, "read timed out"
    end

    def self.next_from_io io
        if line = readline(io)
            fields = line.split SEPARATOR, FIELD_COUNT
            hash = {}
            FIELDS.each do |key|
                val = fields.shift
                hash[key] = val.empty? ? nil : val
            end
            return hash
        end
    rescue Exception => e
        Pcap.warning e.message
        return nil
    end

end
end
end
end
