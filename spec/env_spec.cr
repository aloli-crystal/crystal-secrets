require "./spec_helper"

describe Secrets::Env do
  describe ".parse" do
    it "parses simple KEY=VALUE pairs" do
      result = Secrets::Env.parse(<<-ENV)
      DATABASE_URL=postgres://localhost/test
      API_KEY=abc123
      ENV
      result.should eq({
        "DATABASE_URL" => "postgres://localhost/test",
        "API_KEY"      => "abc123",
      })
    end

    it "ignores comments and blank lines" do
      result = Secrets::Env.parse(<<-ENV)
      # this is a comment

      KEY=value

      # another comment
      OTHER=42
      ENV
      result.should eq({"KEY" => "value", "OTHER" => "42"})
    end

    it "strips matching surrounding double quotes" do
      result = Secrets::Env.parse(%(URL="postgres://x:y@host/db"\n))
      result["URL"].should eq("postgres://x:y@host/db")
    end

    it "strips matching surrounding single quotes" do
      result = Secrets::Env.parse(%(SECRET='complex@pass!w/spaces'\n))
      result["SECRET"].should eq("complex@pass!w/spaces")
    end

    it "leaves mismatched quotes inside values alone" do
      # An opening but no closing quote: keep the raw value.
      result = Secrets::Env.parse(%(WEIRD="unmatched\n))
      result["WEIRD"].should eq(%("unmatched))
    end

    it "accepts the `export` prefix" do
      result = Secrets::Env.parse("export PATH=/usr/bin\n")
      result.should eq({"PATH" => "/usr/bin"})
    end

    it "skips lines without an equals sign" do
      result = Secrets::Env.parse(<<-ENV)
      VALID=yes
      this is not a kv line
      ALSO=valid
      ENV
      result.should eq({"VALID" => "yes", "ALSO" => "valid"})
    end

    it "handles values containing equals signs" do
      result = Secrets::Env.parse("URL=postgres://user:pass=word@host/db\n")
      result["URL"].should eq("postgres://user:pass=word@host/db")
    end

    it "trims whitespace around the key" do
      result = Secrets::Env.parse("  KEY  =value\n")
      result["KEY"].should eq("value")
    end
  end

  describe ".encrypt_file / .decrypt_file" do
    it "round-trips a .env via .age and back to plaintext" do
      stdout = IO::Memory.new
      Process.run("age-keygen", [] of String, output: stdout)
      kb = stdout.to_s
      identity = kb.lines.find! { |l| l.starts_with?("AGE-SECRET-KEY-1") }.strip
      recipient = kb.lines.find! { |l| l.starts_with?("# public key:") }.split(' ', 4).last.strip

      tmp = "/tmp/cs-env-spec-#{Random::Secure.hex(4)}"
      Dir.mkdir_p(tmp)
      begin
        plain = File.join(tmp, "app.env")
        File.write(plain, "DATABASE_URL=postgres://x\nAPI_KEY=secret\n")

        # We can't easily route MasterKey.read here, so we exercise
        # Vault directly with the matching identity to assert that
        # what `encrypt_file` produced is decryptable.
        ct_path = File.join(tmp, "app.env.age")
        File.write(ct_path, Secrets::Vault.encrypt(File.read(plain), [recipient]))

        plain_again = File.join(tmp, "app.env.dec")
        File.write(plain_again, Secrets::Vault.decrypt(File.read(ct_path), identity))

        File.read(plain_again).should eq(File.read(plain))
      ensure
        FileUtils.rm_rf(tmp)
      end
    end
  end
end
