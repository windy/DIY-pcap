# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "diy/version"

Gem::Specification.new do |s|
  s.name        = "DIY-pcap"
  s.version     = DIY::PCAP::VERSION
  s.authors     = ["yafei Lee"]
  s.email       = ["lyfi2003@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{DIY pcap send and recv}
  s.description = %q{DIY pcap send and recv}
  
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.add_dependency "ffi-pcap", ">=0.2.0"
end
