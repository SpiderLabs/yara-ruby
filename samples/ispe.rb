#!/usr/bin/env ruby
#
# Usage example:
#   ruby ispe.rb /win_c/windows/system32/*.???
#
$: << File.join(File.dirname(__FILE__), '..', 'lib')
require 'yara'

ctx = Yara::Rules.new
ctx.compile_string "rule IsPE { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"

ARGV.each do |fname|
  ctx.scan_file(fname).each {|match| puts "#{fname} -> #{match.rule}" }
end
