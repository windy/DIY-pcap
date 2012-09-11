require 'spec_helper'

describe DIY::Builder do
  it "should respond before_send" do
    DIY::Builder.new { ; }.should be_respond_to("before_send")
  end
end