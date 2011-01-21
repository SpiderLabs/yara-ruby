#!/usr/bin/env ruby
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
$: << 'lib'
require 'yara'
require 'pp'

rule_str = <<_EOF_
  rule UPX {
      strings:
          $noep1 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
          $noep2 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 }
          $noep3 = { 01 DB [0-1] 07 8B 1E 83 EE FC 11 DB [1-4] B8 01 00 00 00 01 DB }
          $noep4 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 }
          $noep5 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
          $noep6 = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
          $noep7 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 }
          $noep8 = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
          $ep1 = { 60 E8 00 00 00 00 58 83 E8 3D }
          $ep2 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }
          $ep3 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
          
      condition: any of ($noep*) or for any of ($ep*) : ($ at entrypoint)
  }
_EOF_

ctx = Yara::Rules.new
ctx.compile_string rule_str

ARGV.each do |fname|
  begin
    ctx.scan_file(fname).each do |match|
      pp match
    end
  rescue Yara::ScanError => e
    STDERR.puts e
  end
end
  

