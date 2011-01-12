
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

    def inspect
      h=to_hash
      h.inspect
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

    def inspect
      h=to_a
      h.inspect
    end
  end

end
