# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'mu/pcap/reader'
require 'stringio'
require 'zlib'

module Mu
class Pcap
class Reader

# Reader for HTTP family of protocols (HTTP/SIP/RTSP).
# Handles message boundaries and decompressing/dechunking payloads.
class HttpFamily < Reader
    FAMILY = :http
    FAMILY_TO_READER[FAMILY] = self
    CRLF = "\r\n"
    def family
        FAMILY
    end

    def do_record_write bytes, state=nil
        return if not state
        if bytes =~ RE_REQUEST_LINE
            method  = $1
            requests = state[:requests] ||= []
            requests << method
        end
    end
    private :do_record_write

    RE_CONTENT_ENCODING = /^content-encoding:\s*(gzip|deflate)/i
    RE_CHUNKED = /Transfer-Encoding:\s*chunked/i
    RE_HEADERS_COMPLETE = /.*?\r\n\r\n/m
    # Request line e.g. GET /index.html HTTP/1.1
    RE_REQUEST_LINE = /\A([^ \t\r\n]+)[ \t]+([^ \t\r\n]+)[ \t]+(HTTP|SIP|RTSP)\/[\d.]+.*\r\n/
    # Status line e.g. SIP/2.0 404 Authorization required
    RE_STATUS_LINE = /\A((HTTP|SIP|RTSP)\/[\d.]+[ \t]+(\d+))\b.*\r\n/

    RE_CONTENT_LENGTH = /^(Content-Length)(:\s*)(\d+)\r\n/i
    RE_CONTENT_LENGTH_SIP = /^(Content-Length|l)(:\s*)(\d+)\r\n/i


    def do_read_message! bytes, state=nil
        case bytes
        when RE_REQUEST_LINE
            proto = $3
        when RE_STATUS_LINE
            proto = $2
            status = $3.to_i
            if state
                requests = state[:requests] ||= []
                if requests[0] == "HEAD"
                    reply_to_head = true
                end
                if status > 199
                    # We have a final response. Forget about request.
                    requests.shift
                end
            end
        else
            return nil # Not http family.
        end

        # Read headers
        if bytes =~ RE_HEADERS_COMPLETE
            headers = $&
            rest = $'
        else
            return nil
        end
        message = [headers]

        # Read payload.
        if proto == 'SIP'
            re_content_length = RE_CONTENT_LENGTH_SIP
        else
            re_content_length = RE_CONTENT_LENGTH
        end
        if reply_to_head
            length = 0
        elsif headers =~ RE_CHUNKED
            # Read chunks, dechunking in runtime case.
            raw, dechunked = get_chunks(rest)
            if raw
                length = raw.length
                payload =  raw 
            else
                return nil # Last chunk not received.
            end
        elsif headers =~ re_content_length
            length = $3.to_i
            if rest.length >= length
                payload = rest.slice(0,length)
            else
                return nil # Not enough bytes.
            end
        else
            # XXX. When there is a payload and no content-length
            # header HTTP RFC says to read until connection close.
            length = 0
        end

        message << payload

        # Consume message from input bytes.
        message_len = headers.length + length
        if bytes.length >= message_len
            bytes.slice!(0, message_len)
            return message.join
        else
            return nil # Not enough bytes.
        end
    end
    private :do_read_message!

    # Returns array containing raw and dechunked payload. Returns nil
    # if payload cannot be completely read.
    RE_CHUNK_SIZE_LINE = /\A([[:xdigit:]]+)\r\n?/
    def get_chunks bytes
        raw = []
        dechunked = []
        io = StringIO.new bytes
        until io.eof?
            # Read size line
            size_line = io.readline 
            raw << size_line
            if size_line =~ RE_CHUNK_SIZE_LINE
                chunk_size = $1.to_i(16)
            else
                # Malformed chunk size line
                $stderr.puts "malformed size line : #{size_line.inspect}"
                return nil
            end

            # Read chunk data
            chunk = io.read(chunk_size)
            if chunk.size < chunk_size
                # malformed/incomplete
                $stderr.puts "malformed/incomplete #{chunk_size}"
                return nil
            end
            raw << chunk
            dechunked << chunk
            # Get end-of-chunk CRLF
            crlf = io.read(2)
            if crlf == CRLF
                raw << crlf
            else
                # CRLF has not arrived or, if this is the last chunk,
                # we might be looking at the first two bytes of a trailer
                # and we don't support trailers (see rfc 2616 sec3.6.1).
                return nil
            end

            if chunk_size == 0
                # Done. Return raw and dechunked payloads.
                return raw.join, dechunked.join
            end
        end

        # EOF w/out reaching last chunk.
        return nil
    end
end

end
end
end
