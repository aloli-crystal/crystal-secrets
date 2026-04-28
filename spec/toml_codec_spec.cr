require "./spec_helper"

describe CrystalSecrets::TomlCodec do
  describe ".parse" do
    it "parses top-level scalars as String" do
      doc = CrystalSecrets::TomlCodec.parse(<<-TOML)
        DATABASE_URL = "postgres://x"
        API_KEY = "abc"
        TOML
      doc["DATABASE_URL"].should eq("postgres://x")
      doc["API_KEY"].should eq("abc")
    end

    it "parses sections as Hash(String, String)" do
      doc = CrystalSecrets::TomlCodec.parse(<<-TOML)
        [stripe]
        secret_key = "sk_live_..."
        webhook = "whsec_..."
        TOML
      stripe = doc["stripe"].as(Hash(String, String))
      stripe["secret_key"].should eq("sk_live_...")
      stripe["webhook"].should eq("whsec_...")
    end

    it "preserves multi-line literal strings" do
      cert = <<-CERT
        -----BEGIN CERTIFICATE-----
        AAAAA
        -----END CERTIFICATE-----
        CERT
      doc = CrystalSecrets::TomlCodec.parse(<<-TOML)
        [tls]
        cert = '''
        #{cert}'''
        TOML
      doc["tls"].as(Hash)["cert"].should contain("BEGIN CERTIFICATE")
    end

    it "raises TomlError on bad TOML" do
      expect_raises(CrystalSecrets::TomlError) do
        CrystalSecrets::TomlCodec.parse("not = valid = toml")
      end
    end
  end

  describe ".serialize" do
    it "writes top-level pairs first, then sections" do
      doc = CrystalSecrets::TomlCodec::Doc.new
      doc["DATABASE_URL"] = "postgres://x"
      doc["API_KEY"] = "abc"
      stripe = {} of String => String
      stripe["secret_key"] = "sk_live_..."
      doc["stripe"] = stripe

      out = CrystalSecrets::TomlCodec.serialize(doc)
      out.should contain("DATABASE_URL = \"postgres://x\"")
      out.should contain("API_KEY = \"abc\"")
      out.should contain("[stripe]")
      out.should contain("secret_key = \"sk_live_...\"")
    end

    it "escapes special characters in values" do
      doc = CrystalSecrets::TomlCodec::Doc.new
      doc["with_quotes"] = %{a"b\\c}
      doc["with_tab"] = "a\tb"
      out = CrystalSecrets::TomlCodec.serialize(doc)
      out.should contain(%{with_quotes = "a\\"b\\\\c"})
      out.should contain(%{with_tab = "a\\tb"})
    end

    it "uses '''…''' for multi-line values" do
      doc = CrystalSecrets::TomlCodec::Doc.new
      doc["pem"] = "-----BEGIN-----\nABC\n-----END-----"
      out = CrystalSecrets::TomlCodec.serialize(doc)
      out.should contain("'''")
      out.should contain("BEGIN")
      out.should contain("END")
    end

    it "round-trips a typical vault" do
      doc = CrystalSecrets::TomlCodec::Doc.new
      doc["DATABASE_URL"] = "postgres://aloli:secret@db/prod"
      doc["API_KEY"] = "ak_live_xyz"
      stripe = {} of String => String
      stripe["secret_key"] = "sk_live_abc"
      stripe["webhook_secret"] = "whsec_def"
      doc["stripe"] = stripe

      serialized = CrystalSecrets::TomlCodec.serialize(doc)
      reparsed = CrystalSecrets::TomlCodec.parse(serialized)
      reparsed["DATABASE_URL"].should eq("postgres://aloli:secret@db/prod")
      reparsed["API_KEY"].should eq("ak_live_xyz")
      reparsed["stripe"].as(Hash(String, String))["secret_key"].should eq("sk_live_abc")
      reparsed["stripe"].as(Hash(String, String))["webhook_secret"].should eq("whsec_def")
    end
  end
end
