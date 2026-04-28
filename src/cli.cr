require "option_parser"
require "file_utils"
require "./crystal_secrets"

# Convention Aloli : every long flag has a short equivalent ; every
# subcommand has a short alias.
module CrystalSecrets::CLI
  extend self

  DEFAULT_VAULT_DIR = "#{ENV["HOME"]}/.config/crystal-secrets/vaults"
  DEFAULT_WORDS     = 7

  def run(argv : Array(String)) : Int32
    if argv.empty?
      print_global_help(STDERR)
      return 64
    end

    case argv.first
    when "init", "i"        then init(argv[1..-1])
    when "vault", "vt"      then vault(argv[1..-1])
    when "get", "g"         then get(argv[1..-1])
    when "set", "s"         then set_cmd(argv[1..-1])
    when "list", "ls"       then list_cmd(argv[1..-1])
    when "master-key", "mk" then master_key(argv[1..-1])
    when "version", "v", "--version", "-V"
      puts "crystal-secrets #{CrystalSecrets::VERSION}"
      0
    when "help", "h", "--help", "-h"
      print_global_help(STDOUT)
      0
    else
      STDERR.puts "unknown subcommand: #{argv.first}"
      print_global_help(STDERR)
      64
    end
  end

  # ====================================================================
  # init
  # ====================================================================

  def init(argv : Array(String)) : Int32
    words = DEFAULT_WORDS
    language : Symbol? = nil
    force = false

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-secrets init [options]"
      parser.on("-w N", "--words=N", "Diceware passphrase length (default: #{DEFAULT_WORDS})") { |v| words = v.to_i }
      parser.on("-l LANG", "--language=LANG", "Diceware wordlist (eff_long | fr_mbelivo_5d ; default: auto via $LANG)") do |v|
        language = case v
                   when "eff_long"      then :eff_long
                   when "fr_mbelivo_5d" then :fr_mbelivo_5d
                   else
                     STDERR.puts "unknown language: #{v}"
                     exit 64
                   end
      end
      parser.on("-f", "--force", "Overwrite an existing master key (DESTRUCTIVE)") { force = true }
      parser.on("-h", "--help", "Show this help") { puts parser; exit 0 }
      parser.invalid_option do |flag|
        STDERR.puts "invalid option: #{flag}"
        STDERR.puts parser
        exit 64
      end
    end

    keypair = CrystalSecrets::MasterKey.generate!(force: force)

    suggested = ::Diceware.generate(words: words, language: language)
    puts ""
    puts "Generated Diceware passphrase (#{words} words):"
    puts ""
    puts "    #{suggested}"
    puts ""
    print "Accept this passphrase? [O/r/n] "
    answer = STDIN.gets.try(&.strip.downcase) || ""

    passphrase = case answer
                 when "", "o", "y"
                   suggested
                 when "r"
                   loop do
                     try = ::Diceware.generate(words: words, language: language)
                     puts "    #{try}"
                     print "Accept? [O/r/n] "
                     a = STDIN.gets.try(&.strip.downcase) || ""
                     break try if a.empty? || a == "o" || a == "y"
                     break read_user_passphrase if a == "n"
                   end
                 when "n"
                   read_user_passphrase
                 else
                   STDERR.puts "unrecognized answer; aborting"
                   return 64
                 end

    paper = CrystalSecrets::Recovery.export(keypair.identity, passphrase)

    puts ""
    puts "════════════════════════════════════════════════════════════════════"
    puts "  PUBLIC KEY (add this to your team recipients.txt) :"
    puts ""
    puts "    #{keypair.recipient}"
    puts ""
    puts "════════════════════════════════════════════════════════════════════"
    puts "  PAPER RECOVERY CODE — print this and store in a physical safe."
    puts "  Anyone with the passphrase below + this paper can recover your"
    puts "  master key. NEVER photograph, NEVER scan."
    puts "════════════════════════════════════════════════════════════════════"
    puts ""
    puts "  Passphrase :"
    puts "      #{passphrase}"
    puts ""
    puts paper
    puts "════════════════════════════════════════════════════════════════════"
    puts ""
    puts "Master key stored in Keychain (account: #{CrystalSecrets::MasterKey::KEYCHAIN_ACCOUNT})."
    0
  rescue ex
    STDERR.puts "init failed: #{ex.message}"
    1
  end

  # ====================================================================
  # vault
  # ====================================================================

  def vault(argv : Array(String)) : Int32
    return 64 if argv.empty?
    case argv.first
    when "create", "c"
      vault_create(argv[1..-1])
    else
      STDERR.puts "unknown vault subcommand: #{argv.first}"
      64
    end
  end

  def vault_create(argv : Array(String)) : Int32
    name = ""
    vault_dir = DEFAULT_VAULT_DIR

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-secrets vault create -n NAME [options]"
      parser.on("-n NAME", "--name=NAME", "Vault name (e.g. prod, staging)") { |v| name = v }
      parser.on("-d DIR", "--vault-dir=DIR", "Vault directory (default: #{DEFAULT_VAULT_DIR})") { |v| vault_dir = v }
      parser.on("-h", "--help", "Show this help") { puts parser; exit 0 }
    end

    if name.empty? && argv.size >= 1 && !argv.first.starts_with?("-")
      name = argv.first
    end
    if name.empty?
      STDERR.puts "missing -n/--name"
      return 64
    end

    Dir.mkdir_p(vault_dir)
    File.chmod(vault_dir, 0o700)
    path = File.join(vault_dir, "#{name}.toml.age")
    if File.exists?(path)
      STDERR.puts "vault already exists: #{path}"
      return 1
    end

    keypair = CrystalSecrets::MasterKey.read
    initial = "# vault: #{name} (created #{Time.utc.to_s("%Y-%m-%d")})\n"
    ciphertext = CrystalSecrets::Vault.encrypt(initial, keypair.recipient)
    File.write(path, ciphertext)
    File.chmod(path, 0o600)

    puts "vault created: #{path}"
    0
  rescue ex
    STDERR.puts "vault create failed: #{ex.message}"
    1
  end

  # ====================================================================
  # get
  # ====================================================================

  def get(argv : Array(String)) : Int32
    vault_name, key, vault_dir = parse_vault_key_args(argv, "get")
    return 64 if vault_name.empty? || key.empty?

    doc = read_vault(vault_name, vault_dir)
    if value = doc.string?(key)
      puts value
      return 0
    end
    STDERR.puts "key not found: #{key}"
    1
  rescue ex
    STDERR.puts "get failed: #{ex.message}"
    1
  end

  # ====================================================================
  # set
  # ====================================================================

  def set_cmd(argv : Array(String)) : Int32
    vault_name, key, vault_dir = parse_vault_key_args(argv, "set")
    return 64 if vault_name.empty? || key.empty?

    print "Value (hidden): "
    STDOUT.flush
    value = read_secret_from_stdin
    if value.nil? || value.empty?
      STDERR.puts "no value provided; aborting"
      return 64
    end

    doc = read_vault(vault_name, vault_dir)
    doc.set(key, value)
    write_vault(vault_name, vault_dir, doc)

    puts "set #{key} in #{vault_name}"
    0
  rescue ex
    STDERR.puts "set failed: #{ex.message}"
    1
  end

  # ====================================================================
  # list
  # ====================================================================

  def list_cmd(argv : Array(String)) : Int32
    vault_name = ""
    vault_dir = DEFAULT_VAULT_DIR

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-secrets list -n VAULT [options]"
      parser.on("-n NAME", "--name=NAME", "Vault name") { |v| vault_name = v }
      parser.on("-d DIR", "--vault-dir=DIR", "Vault directory") { |v| vault_dir = v }
      parser.on("-h", "--help", "Show this help") { puts parser; exit 0 }
    end

    if vault_name.empty? && argv.size >= 1 && !argv.first.starts_with?("-")
      vault_name = argv.first
    end
    if vault_name.empty?
      STDERR.puts "missing vault name"
      return 64
    end

    doc = read_vault(vault_name, vault_dir)
    doc.to_h.each do |key, value|
      case value
      when Hash
        value.each_key { |sub| puts "#{key}.#{sub}" }
      else
        puts key
      end
    end
    0
  rescue ex
    STDERR.puts "list failed: #{ex.message}"
    1
  end

  # ====================================================================
  # master-key
  # ====================================================================

  def master_key(argv : Array(String)) : Int32
    return 64 if argv.empty?
    case argv.first
    when "export", "x"
      master_key_export(argv[1..-1])
    when "import", "m"
      master_key_import(argv[1..-1])
    else
      STDERR.puts "unknown master-key subcommand: #{argv.first}"
      64
    end
  end

  def master_key_export(argv : Array(String)) : Int32
    keypair = CrystalSecrets::MasterKey.read
    print "Passphrase (hidden): "
    STDOUT.flush
    passphrase = read_secret_from_stdin
    if passphrase.nil? || passphrase.empty?
      STDERR.puts "no passphrase provided; aborting"
      return 64
    end
    paper = CrystalSecrets::Recovery.export(keypair.identity, passphrase)
    puts paper
    0
  rescue ex
    STDERR.puts "master-key export failed: #{ex.message}"
    1
  end

  def master_key_import(argv : Array(String)) : Int32
    STDERR.puts "Paste the recovery paper, then Ctrl-D :"
    paper = STDIN.gets_to_end
    print "Passphrase (hidden): "
    STDOUT.flush
    passphrase = read_secret_from_stdin
    if passphrase.nil? || passphrase.empty?
      STDERR.puts "no passphrase provided; aborting"
      return 64
    end
    identity = CrystalSecrets::Recovery.import(paper, passphrase)
    keypair = CrystalSecrets::MasterKey.install!(identity)
    puts "master key restored. Public key:"
    puts "    #{keypair.recipient}"
    0
  rescue ex
    STDERR.puts "master-key import failed: #{ex.message}"
    1
  end

  # ====================================================================
  # helpers
  # ====================================================================

  private def parse_vault_key_args(argv : Array(String), cmd : String) : Tuple(String, String, String)
    vault_name = ""
    key = ""
    vault_dir = DEFAULT_VAULT_DIR

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-secrets #{cmd} -n VAULT -k KEY [options]"
      parser.on("-n NAME", "--name=NAME", "Vault name (e.g. prod)") { |v| vault_name = v }
      parser.on("-k KEY", "--key=KEY", "Secret key (e.g. DATABASE_URL or stripe.secret_key)") { |v| key = v }
      parser.on("-d DIR", "--vault-dir=DIR", "Vault directory") { |v| vault_dir = v }
      parser.on("-h", "--help", "Show this help") { puts parser; exit 0 }
    end

    # Positional fallback : cmd VAULT KEY
    positional = argv.reject { |a| a.starts_with?("-") }
    vault_name = positional[0] if vault_name.empty? && positional.size >= 1
    key = positional[1] if key.empty? && positional.size >= 2

    {vault_name, key, vault_dir}
  end

  private def read_vault(name : String, vault_dir : String) : ::TOML::Document
    path = File.join(vault_dir, "#{name}.toml.age")
    raise "vault not found: #{path}. Did you run `crystal-secrets vault create`?" unless File.exists?(path)
    keypair = CrystalSecrets::MasterKey.read
    ciphertext = File.read(path)
    plaintext = CrystalSecrets::Vault.decrypt(ciphertext, keypair.identity)
    ::TOML.parse(plaintext)
  end

  private def write_vault(name : String, vault_dir : String, doc : ::TOML::Document) : Nil
    path = File.join(vault_dir, "#{name}.toml.age")
    keypair = CrystalSecrets::MasterKey.read
    plaintext = doc.to_toml
    ciphertext = CrystalSecrets::Vault.encrypt(plaintext, keypair.recipient)
    File.write(path, ciphertext)
    File.chmod(path, 0o600)
  end

  private def read_secret_from_stdin : String?
    # Hide echo when STDIN is a terminal; otherwise read the line as-is
    # (allows piped input for scripts).
    if STDIN.tty?
      STDIN.noecho { STDIN.gets.try(&.chomp) }.tap { puts }
    else
      STDIN.gets.try(&.chomp)
    end
  end

  private def read_user_passphrase : String
    print "Enter your own passphrase: "
    STDOUT.flush
    p = read_secret_from_stdin
    raise "no passphrase provided" if p.nil? || p.empty?
    p
  end

  private def print_global_help(io : IO)
    io.puts "Usage: crystal-secrets SUBCOMMAND [options]"
    io.puts
    io.puts "Subcommands :"
    io.puts "  init,  i               Generate the master key and the recovery paper"
    io.puts "  vault, vt   create     Create a new vault file"
    io.puts "  get,   g               Read a secret"
    io.puts "  set,   s               Write a secret (value via stdin)"
    io.puts "  list,  ls              List the keys of a vault"
    io.puts "  master-key, mk         Manage the master key (export/import)"
    io.puts "  version, v             Print version"
    io.puts "  help,    h             Show this help"
    io.puts
    io.puts "Run `crystal-secrets SUBCOMMAND -h` for subcommand-specific options."
  end
end

exit CrystalSecrets::CLI.run(ARGV) if PROGRAM_NAME.includes?("crystal-secrets") || PROGRAM_NAME.includes?("cli")
