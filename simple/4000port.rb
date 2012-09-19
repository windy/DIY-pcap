$LOAD_PATH.unshift File.join( File.dirname(__FILE__), '..', 'lib' )
require 'rubygems'
require 'diy/pcap'

# client and server
DIY::PCAP.new do |s|
  s.dir = File.join( File.dirname(__FILE__), '4000port')
  s.send("s1.dat")
  s.recv("r1.dat")
  s.send("s2.dat")
  s.send("s3.dat")
  s.recv("r3.dat")
  s.send("s4.dat")
  s.recv("r4.dat")
  s.send("s5.dat")
  s.send("s6.dat")
  s.recv("r6.dat")
  s.recv("r7.dat")
  s.send("s8.dat")
end