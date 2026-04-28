require "random/secure"
require "./error"

module CrystalSecrets
  # Diceware passphrase generator — local v0.1 implementation.
  #
  # Will be replaced by the standalone `crystal-diceware` shard once it
  # is published. Until then, this module embeds two wordlists (English
  # EFF Large + French mbelivo 5d) and produces passphrases of N words
  # tirées avec `Random::Secure`.
  #
  # Each wordlist has 7776 entries (= 6^5) so a roll of five 6-sided
  # dice maps to one word, à la Reinhold 1995. Entropy per word =
  # log2(7776) ≈ 12.92 bits.
  module Diceware
    extend self

    # 5 digits, each in 1..6
    record Roll, digits : StaticArray(Int32, 5) do
      def self.from_string(s : String) : Roll
        raise DicewareError.new("roll must be 5 chars, got #{s.bytesize}") unless s.bytesize == 5
        digits = StaticArray(Int32, 5).new { |i| s[i].to_i }
        5.times do |i|
          d = digits[i]
          raise DicewareError.new("digit #{i} of '#{s}' is #{d}, must be in 1..6") unless 1 <= d <= 6
        end
        new(digits)
      end

      def self.from_random : Roll
        new(StaticArray(Int32, 5).new { Random::Secure.rand(1..6) })
      end

      # Convert dice digits (each 1..6) into a 0-based index into the
      # 7776-word list, treating digits as base-6.
      def to_index : Int32
        idx = 0
        5.times do |i|
          idx = idx * 6 + (digits[i] - 1)
        end
        idx
      end

      def to_s(io : IO) : Nil
        digits.each { |d| io << d }
      end
    end

    EFF_LONG      = parse_wordlist({{read_file("#{__DIR__}/wordlists/eff_large_wordlist.txt")}})
    FR_MBELIVO_5D = parse_wordlist({{read_file("#{__DIR__}/wordlists/fr_mbelivo_5d.txt")}})

    # Catalog: identifier -> {language, words}
    record Wordlist, id : Symbol, language : Symbol, words : Array(String) do
      def size : Int32
        words.size
      end

      def lookup(roll : Roll) : String
        words[roll.to_index]
      end
    end

    WORDLISTS = {
      :eff_long      => Wordlist.new(:eff_long, :en, EFF_LONG),
      :fr_mbelivo_5d => Wordlist.new(:fr_mbelivo_5d, :fr, FR_MBELIVO_5D),
    }

    # Pick a wordlist by id, or auto-detect from $LANG.
    def wordlist(id : Symbol? = nil) : Wordlist
      if id
        WORDLISTS[id]? || raise DicewareError.new("unknown wordlist: #{id}")
      else
        lang = (ENV["LANG"]? || "en").downcase
        if lang.starts_with?("fr")
          WORDLISTS[:fr_mbelivo_5d]
        else
          WORDLISTS[:eff_long]
        end
      end
    end

    # Generate a passphrase of `words` words, separated by spaces.
    def generate(words : Int32, language : Symbol? = nil) : String
      raise DicewareError.new("words must be >= 1") if words < 1
      list = wordlist(language)
      Array.new(words) { list.lookup(Roll.from_random) }.join(' ')
    end

    # Convert a list of explicit dice rolls into a passphrase.
    def generate_from_rolls(rolls : Array(String), language : Symbol? = nil) : String
      raise DicewareError.new("rolls must not be empty") if rolls.empty?
      list = wordlist(language)
      rolls.map { |s| list.lookup(Roll.from_string(s)) }.join(' ')
    end

    # Hybrid: K random rolls then the supplied manual rolls.
    def generate_hybrid(auto_count : Int32, manual_rolls : Array(String),
                        language : Symbol? = nil) : String
      raise DicewareError.new("auto_count must be >= 0") if auto_count < 0
      list = wordlist(language)
      result = [] of String
      auto_count.times { result << list.lookup(Roll.from_random) }
      manual_rolls.each { |s| result << list.lookup(Roll.from_string(s)) }
      result.join(' ')
    end

    # Entropy in bits for a passphrase of `words` words from a wordlist.
    def entropy(words : Int32, language : Symbol? = nil) : Float64
      list = wordlist(language)
      words * Math.log2(list.size.to_f64)
    end

    # ==== private ========================================================

    private def self.parse_wordlist(text : String) : Array(String)
      words = Array(String).new(7776)
      text.each_line do |line|
        line = line.strip
        next if line.empty?
        # "11111\tabacus" or "11111 abaisse" — split on first run of whitespace
        parts = line.split(/\s+/, 2)
        raise DicewareError.new("malformed wordlist line: #{line.inspect}") if parts.size != 2
        words << parts[1]
      end
      raise DicewareError.new("wordlist must have 7776 entries, got #{words.size}") unless words.size == 7776
      raise DicewareError.new("wordlist has duplicate entries") if words.uniq.size != words.size
      words
    end
  end
end
