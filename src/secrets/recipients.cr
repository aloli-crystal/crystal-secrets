require "toml"
require "file_utils"
require "./error"

module Secrets
  # Multi-recipient roster for vault encryption.
  #
  # The roster lives in `${XDG_CONFIG_HOME:-~/.config}/secrets/recipients.toml`,
  # a plain TOML file safe to commit to git (it only contains *public*
  # keys). Format:
  #
  #     [recipients]
  #     philippe = "age1xxx..."
  #     alice    = "age1yyy..."
  #     bob      = "age1zzz..."
  #
  # When a vault is written out, the union of all keys in this file
  # plus the operator's own master key is passed to age, so any
  # listed identity can later decrypt. If the file is absent, the
  # operator's master key alone is used (= v0.3 single-recipient
  # behaviour, transparent for solo users).
  #
  # The operator's own key is auto-included to prevent locking
  # oneself out by typo.
  module Recipients
    extend self

    RECIPIENTS_FILE = "#{Secrets::CONFIG_DIR}/recipients.toml"

    # Public keys (in age1... form) to encrypt the next vault write
    # against. Always includes the operator's own master key.
    def encryption_keys : Array(String)
      own = Secrets::MasterKey.read.recipient
      keys = list_named.values.dup
      keys << own unless keys.includes?(own)
      keys
    end

    # `name => age1key` map of every entry in `recipients.toml`.
    # Empty hash if the file is absent.
    def list_named : Hash(String, String)
      return {} of String => String unless File.exists?(RECIPIENTS_FILE)
      doc = ::TOML.parse(File.read(RECIPIENTS_FILE))
      hash = doc.to_h["recipients"]?
      return {} of String => String unless hash.is_a?(Hash)
      result = {} of String => String
      hash.each do |k, v|
        result[k.to_s] = v.as(String) if v.is_a?(String)
      end
      result
    end

    # Add or update a named recipient. Validates the public key
    # format. Persists `recipients.toml` (creates the file with mode
    # 0644 on first call — public keys are not secret).
    def add(name : String, key : String) : Nil
      raise Error.new("recipient key must start with 'age1' (got: #{key[0..15]}...)") unless key.starts_with?("age1")
      raise Error.new("recipient name must not be empty") if name.empty?
      raise Error.new("recipient name must not contain '.' (used as TOML key separator)") if name.includes?('.')

      roster = list_named
      roster[name] = key
      write_roster(roster)
    end

    # Remove a named recipient. Returns true if removed, false if the
    # name was not in the roster.
    def remove(name : String) : Bool
      roster = list_named
      return false unless roster.has_key?(name)
      roster.delete(name)
      write_roster(roster)
      true
    end

    # Serialise the roster back to `recipients.toml`. We write the
    # file by hand rather than going through `TOML::Document.set`
    # because the latter treats `recipients.alice` as a literal
    # quoted key, not as a path into the `[recipients]` table.
    private def write_roster(roster : Hash(String, String)) : Nil
      Dir.mkdir_p(Secrets::CONFIG_DIR)
      File.chmod(Secrets::CONFIG_DIR, 0o700)

      content = String.build do |io|
        io << "# secrets — team recipients roster (versionable, no secrets)\n"
        io << "# Add a member: secrets recipients add NAME age1...\n"
        io << "# After every add/remove, run `secrets rotation -n VAULT` on each\n"
        io << "# vault that should be readable by the new roster.\n\n"
        io << "[recipients]\n"
        roster.keys.sort.each do |name|
          io << name << " = \"" << roster[name] << "\"\n"
        end
      end
      File.write(RECIPIENTS_FILE, content)
      File.chmod(RECIPIENTS_FILE, 0o644)
    end
  end
end
