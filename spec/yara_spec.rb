require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Yara do
  it "should be a module" do
    Yara.should be_kind_of(Module)
  end

end
