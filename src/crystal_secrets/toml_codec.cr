require "toml"
require "./error"

module CrystalSecrets
  # Reads and writes the in-vault TOML representation.
  #
  # Read path uses `crystal-community/TOML.cr` which gives us a
  # `Hash(String, TOML::Type)`. Write path is a tiny custom serializer
  # that handles the subset we need: top-level `key = "string"` lines,
  # `[section]` headers, and `key = "string"` lines inside sections.
  #
  # v0.1 design choices :
  #
  # * Every leaf value is serialized as a TOML basic string. Multi-line
  #   payloads (PEM, kubeconfigs) use `'''…'''` literal strings.
  # * Comments written by the user manually are NOT preserved across
  #   programmatic `set`. Use `crystal-secrets edit` to keep comments.
  # * Sections are nested **one level deep only** in v0.1
  #   (`[stripe]`, `[ovh]`, …). Nested `[a.b.c]` is parsed if present
  #   but flattened on write.
  module TomlCodec
    extend self

    # Decode a TOML string into a flat-or-1-level Hash. The shape is
    # `Hash(String, String | Hash(String, String))` from the caller's
    # point of view.
    alias Doc = Hash(String, String | Hash(String, String))

    def parse(text : String) : Doc
      raw = TOML.parse(text)
      result = Doc.new
      raw.each do |key, value|
        unwrapped = unwrap(value)
        case unwrapped
        when String
          result[key] = unwrapped
        when Hash
          subhash = {} of String => String
          unwrapped.each do |k, v|
            subhash[k] = stringify(unwrap(v))
          end
          result[key] = subhash
        else
          result[key] = stringify(unwrapped)
        end
      end
      result
    rescue ex
      raise TomlError.new("TOML parse error: #{ex.message}")
    end

    # `TOML.parse` returns Hash(String, TOML::Any). Each value's `.raw`
    # is the underlying TOML::Type. Some shard versions expose
    # the value directly without wrapping; handle both.
    private def self.unwrap(value)
      value.responds_to?(:raw) ? value.raw : value
    end

    # Coerce a TOML scalar to a String for our flat Doc representation.
    private def self.stringify(value) : String
      case value
      when String         then value
      when Bool           then value.to_s
      when Int64, Float64 then value.to_s
      when Time           then value.to_s
      when Array          then value.to_s
      when Hash           then value.to_s
      else                     ""
      end
    end

    # Encode a `Doc` back to TOML text. Top-level scalars first, then
    # sections in declaration order, with a blank line between blocks.
    def serialize(doc : Doc) : String
      io = String.build do |s|
        # Top-level scalars (= String values)
        scalars = doc.select { |_, v| v.is_a?(String) }
        scalars.each do |key, value|
          s << format_pair(key, value.as(String)) << '\n'
        end

        # Sections (= Hash values)
        sections = doc.select { |_, v| v.is_a?(Hash) }
        sections.each_with_index do |(key, _value), i|
          subhash = doc[key].as(Hash(String, String))
          # Blank line between top-level and first section, between sections.
          s << '\n'
          s << '[' << key << ']' << '\n'
          subhash.each do |sub_key, sub_val|
            s << format_pair(sub_key, sub_val) << '\n'
          end
        end
      end
      io
    end

    # Format a single `key = value` line. The key is a bare key when
    # possible (ASCII letters/digits/_/-), otherwise quoted.
    private def format_pair(key : String, value : String) : String
      String.build do |s|
        s << format_key(key) << " = " << format_value(value)
      end
    end

    private def format_key(key : String) : String
      if key.matches?(/^[A-Za-z0-9_\-]+$/)
        key
      else
        format_basic_string(key)
      end
    end

    private def format_value(value : String) : String
      # Multi-line literal for strings containing newlines (PEM, etc.)
      if value.includes?('\n')
        # Use literal triple-single-quote so backslashes/quotes pass
        # through verbatim. Refuse if the value contains "'''".
        raise TomlError.new("value contains \"'''\", cannot use literal multi-line") if value.includes?("'''")
        # Per TOML spec, a leading newline immediately after the
        # opening delimiter is trimmed; we add one to make the
        # output prettier.
        "'''\n" + value + "'''"
      else
        format_basic_string(value)
      end
    end

    private def format_basic_string(s : String) : String
      String.build do |io|
        io << '"'
        s.each_char do |c|
          case c
          when '\\' then io << "\\\\"
          when '"'  then io << "\\\""
          when '\b' then io << "\\b"
          when '\f' then io << "\\f"
          when '\n' then io << "\\n"
          when '\r' then io << "\\r"
          when '\t' then io << "\\t"
          else
            if c.ord < 0x20
              io << "\\u" << c.ord.to_s(16, upcase: true).rjust(4, '0')
            else
              io << c
            end
          end
        end
        io << '"'
      end
    end
  end
end
