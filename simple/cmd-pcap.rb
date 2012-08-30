pcap do |s|  
  s.dir = 'pcaps'
  s.send("r1.dat")
  s.recv("s1.dat")
  s.recv("s2.dat")
  s.recv("s3.dat")
  s.send("r3.dat")
end