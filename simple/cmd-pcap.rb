pcap do |s|  
  s.dir = File.join( File.dirname(__FILE__), 'pcaps')
  s.send("r1.dat")
  s.recv("s1.dat")
  s.recv("s2.dat")
  s.recv("s3.dat")
  s.send("r3.dat")
end