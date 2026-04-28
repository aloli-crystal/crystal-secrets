require "./spec_helper"

describe CrystalSecrets::Diceware do
  describe "Roll" do
    it "parses a 5-digit string" do
      r = CrystalSecrets::Diceware::Roll.from_string("13456")
      r.digits.to_a.should eq([1, 3, 4, 5, 6])
    end

    it "round-trips Roll → string" do
      ["11111", "13456", "26611", "66666"].each do |s|
        CrystalSecrets::Diceware::Roll.from_string(s).to_s.should eq(s)
      end
    end

    it "rejects strings not exactly 5 chars" do
      expect_raises(CrystalSecrets::DicewareError, /5 chars/) do
        CrystalSecrets::Diceware::Roll.from_string("1234")
      end
    end

    it "rejects digits outside 1..6" do
      expect_raises(CrystalSecrets::DicewareError, /must be in 1..6/) do
        CrystalSecrets::Diceware::Roll.from_string("12340")
      end
      expect_raises(CrystalSecrets::DicewareError, /must be in 1..6/) do
        CrystalSecrets::Diceware::Roll.from_string("12347")
      end
    end

    it "computes the right index" do
      CrystalSecrets::Diceware::Roll.from_string("11111").to_index.should eq(0)
      CrystalSecrets::Diceware::Roll.from_string("66666").to_index.should eq(7775)
      # Each digit (d-1) * 6^(4-i)
      # Roll 12345 -> (0, 1, 2, 3, 4) -> 0*1296 + 1*216 + 2*36 + 3*6 + 4 = 310
      CrystalSecrets::Diceware::Roll.from_string("12345").to_index.should eq(310)
    end
  end

  describe "wordlist EFF Large (eff_long)" do
    list = CrystalSecrets::Diceware::WORDLISTS[:eff_long]

    it "has 7776 entries" do
      list.size.should eq(7776)
    end

    it "has language :en" do
      list.language.should eq(:en)
    end

    it "matches the official EFF reference vectors" do
      # From https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
      list.lookup(CrystalSecrets::Diceware::Roll.from_string("11111")).should eq("abacus")
      list.lookup(CrystalSecrets::Diceware::Roll.from_string("11112")).should eq("abdomen")
      list.lookup(CrystalSecrets::Diceware::Roll.from_string("66666")).should eq("zoom")
    end

    it "has no duplicates" do
      list.words.uniq.size.should eq(7776)
    end
  end

  describe "wordlist mbelivo French (fr_mbelivo_5d)" do
    list = CrystalSecrets::Diceware::WORDLISTS[:fr_mbelivo_5d]

    it "has 7776 entries" do
      list.size.should eq(7776)
    end

    it "has language :fr" do
      list.language.should eq(:fr)
    end

    it "matches the published reference of mbelivo" do
      # Vérifié sur https://github.com/mbelivo/diceware-wordlists-fr
      list.lookup(CrystalSecrets::Diceware::Roll.from_string("11111")).should eq("abaisse")
      list.lookup(CrystalSecrets::Diceware::Roll.from_string("11112")).should eq("abaisser")
    end

    it "has no duplicates" do
      list.words.uniq.size.should eq(7776)
    end
  end

  describe ".generate" do
    it "produces N space-separated words" do
      phrase = CrystalSecrets::Diceware.generate(words: 7, language: :eff_long)
      phrase.split(' ').size.should eq(7)
    end

    it "produces words actually present in the chosen wordlist" do
      list = CrystalSecrets::Diceware::WORDLISTS[:eff_long]
      phrase = CrystalSecrets::Diceware.generate(words: 5, language: :eff_long)
      phrase.split(' ').each do |word|
        list.words.includes?(word).should be_true
      end
    end

    it "rejects words < 1" do
      expect_raises(CrystalSecrets::DicewareError, />= 1/) do
        CrystalSecrets::Diceware.generate(words: 0)
      end
    end

    it "produces different output across calls (randomness)" do
      a = CrystalSecrets::Diceware.generate(words: 7)
      b = CrystalSecrets::Diceware.generate(words: 7)
      a.should_not eq(b)
    end
  end

  describe ".generate_from_rolls (manual dice mode)" do
    it "converts a sequence of rolls into the corresponding words" do
      phrase = CrystalSecrets::Diceware.generate_from_rolls(
        ["11111", "11112", "66666"],
        language: :eff_long,
      )
      phrase.should eq("abacus abdomen zoom")
    end

    it "rejects an empty rolls array" do
      expect_raises(CrystalSecrets::DicewareError, /empty/) do
        CrystalSecrets::Diceware.generate_from_rolls([] of String)
      end
    end
  end

  describe ".generate_hybrid" do
    it "mixes auto and manual rolls in order" do
      phrase = CrystalSecrets::Diceware.generate_hybrid(
        auto_count: 4,
        manual_rolls: ["11111", "66666"],
        language: :eff_long,
      )
      words = phrase.split(' ')
      words.size.should eq(6)
      words[-2..-1].should eq(["abacus", "zoom"])
    end
  end

  describe ".entropy" do
    it "is exactly N * log2(7776) for a 7776-word list" do
      bits = CrystalSecrets::Diceware.entropy(words: 7, language: :eff_long)
      (bits - 7 * Math.log2(7776)).abs.should be < 1e-10
    end
  end

  describe ".wordlist" do
    it "auto-selects French when LANG=fr_FR.UTF-8" do
      old = ENV["LANG"]?
      begin
        ENV["LANG"] = "fr_FR.UTF-8"
        CrystalSecrets::Diceware.wordlist.id.should eq(:fr_mbelivo_5d)
      ensure
        old.try { |v| ENV["LANG"] = v } || ENV.delete("LANG")
      end
    end

    it "falls back to EFF when LANG is not French" do
      old = ENV["LANG"]?
      begin
        ENV["LANG"] = "en_US.UTF-8"
        CrystalSecrets::Diceware.wordlist.id.should eq(:eff_long)
      ensure
        old.try { |v| ENV["LANG"] = v } || ENV.delete("LANG")
      end
    end
  end
end
