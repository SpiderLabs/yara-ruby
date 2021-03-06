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
require 'yara_native'

module Yara
  class Rules
  end

  class Match
    def to_hash
      { :rule => self.rule, 
        :namespace => self.namespace, 
        :tags => self.tags,
        :meta => self.meta,
        :strings => self.strings }
    end

  end

  class MatchString

    alias ident identifier

    def <=>(other)
      self.offset <=> other.offset
    end

    def to_a
      [self.offset, self.ident, self.buffer]
    end

    def to_hash
      { :offset => self.offset, :identifier => self.ident, :buffer => self.buffer}
    end

  end

end
