#    yara-ruby - Ruby bindings for the yara malware analysis library.
#    Eric Monti
#    Copyright (C) 2011 Trustwave Holdings
#
#    This program is free software: you can redistribute it and/or modify it 
#    under the terms of the GNU General Public License as published by the 
#    Free Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
#    This program is distributed in the hope that it will be useful, but 
#    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
#    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
#    for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program. If not, see <http://www.gnu.org/licenses/>.
#
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
