
require 'yara_native'

module Yara
  class Rules
    class Match
    end

    class MatchString

      def <=>(other)
        self.offset <=> other.offset
      end
    end
  end

end
