$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'rspec'
require 'yara'
require 'digest/md5'

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}


def sample_file(fname)
  File.join(File.dirname(__FILE__), "samples", fname)
end

def md5(buf)
  Digest::MD5.new.update(buf).hexdigest
end

RSpec.configure do |config|
  
end
