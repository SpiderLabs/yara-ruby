#!/usr/bin/env ruby
#
# Usage example:
#   ruby ispe.rb /win_c/windows/system32/*.???
#
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
$: << File.join(File.dirname(__FILE__), '..', 'lib')
require 'yara'

ctx = Yara::Rules.new
ctx.compile_string "rule IsPE { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"

ARGV.each do |fname|
  ctx.scan_file(fname).each {|match| puts "#{fname} -> #{match.rule}" }
end
