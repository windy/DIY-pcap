require 'spec_helper'

describe DIY::Logger do
  it "#debug" do
    lambda { DIY::Logger.info("hello world") }.should_not raise_error
    lambda { DIY::Logger.debug("hello world") }.should_not raise_error
    lambda { DIY::Logger.warn("hello world") }.should_not raise_error
    lambda { DIY::Logger.error("hello world") }.should_not raise_error
  end
  
  it "#add #clear" do
    require 'logger'
    logger = ::Logger.new(STDOUT)
    DIY::Logger.add(logger)
    lambda { DIY::Logger.info("hello world") }.should_not raise_error
    DIY::Logger.clear_and_add(logger)
    lambda { DIY::Logger.info("hello world") }.should_not raise_error
  end
end