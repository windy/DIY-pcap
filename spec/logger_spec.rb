require 'spec_helper'

describe DIY::Logger do
  it "#debug" do
    lambda { DIY::Logger.debug("hello world") }.should_not raise_error
  end
end