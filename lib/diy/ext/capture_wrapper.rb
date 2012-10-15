require 'ffi/pcap'
require 'ffi/pcap/capture_wrapper'

unless defined?(FFI::PCap::CaptureWrapper)
  raise "must define FFI::PCap::CaptureWrapper before monkey fix"
end

module FFI
module PCap 
  class CaptureWrapper
    #  Fix bug: dispatch but call pcap_loop
    #
    def dispatch(opts={}, &block)
      cnt = opts[:count] || -1 # default to infinite loop
      h = opts[:handler]

      ret = FFI::PCap.pcap_dispatch(_pcap, cnt, _wrap_callback(h, block),nil)
      if ret == -1
        raise(ReadError, "pcap_dispatch(): #{geterr()}")
      elsif ret -2
        return nil
      elsif ret > -1
        return ret
      else
        raise(ReadError, "unexpected return from pcap_dispatch() -> #{ret}")
      end
    end
  end
end
end