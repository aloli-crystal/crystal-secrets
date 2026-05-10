require "option_parser"
require "file_utils"
require "./secrets"

# Convention Aloli : every long flag has a short equivalent ; every
# subcommand has a short alias.
module Secrets::CLI
  extend self

  DEFAULT_VAULT_DIR = "#{Secrets::CONFIG_DIR}/vaults"
  LEGACY_VAULT_DIR  = "#{Secrets::XDG_CONFIG_HOME}/crystal-secrets/vaults"
  DEFAULT_WORDS     = 7

  # Transparent rename migration. v0.2.6 moved the default vault dir
  # from `~/.config/crystal-secrets/vaults` to `~/.config/secrets/vaults`.
  # If a user has the legacy dir but not the new one, rename it
  # silently. Idempotent and safe to call on every command.
  private def migrate_legacy_vault_dir
    return if Dir.exists?(DEFAULT_VAULT_DIR)
    return unless Dir.exists?(LEGACY_VAULT_DIR)
    Dir.mkdir_p(File.dirname(DEFAULT_VAULT_DIR))
    File.rename(LEGACY_VAULT_DIR, DEFAULT_VAULT_DIR)
    legacy_parent = File.dirname(LEGACY_VAULT_DIR)
    Dir.delete(legacy_parent) if Dir.exists?(legacy_parent) && Dir.empty?(legacy_parent)
  end

  def run(argv : Array(String)) : Int32
    migrate_legacy_vault_dir

    if argv.empty?
      print_global_help(STDERR)
      return 64
    end

    case argv.first
    when "init", "i"        then init(argv[1..-1])
    when "vault", "vt"      then vault(argv[1..-1])
    when "get", "g"         then get(argv[1..-1])
    when "set", "s"         then set_cmd(argv[1..-1])
    when "delete", "rm"     then delete_cmd(argv[1..-1])
    when "list", "ls"       then list_cmd(argv[1..-1])
    when "edit", "e"        then edit_cmd(argv[1..-1])
    when "rotation", "r"    then rotation_cmd(argv[1..-1])
    when "diff", "df"       then diff_cmd(argv[1..-1])
    when "log", "l"         then log_cmd(argv[1..-1])
    when "master-key", "mk" then master_key(argv[1..-1])
    when "version", "v", "--version", "-V"
      puts "secrets #{Secrets::VERSION}"
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
      parser.banner = "Usage: secrets init [options]"
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

    keypair = Secrets::MasterKey.generate!(force: force)

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

    paper = Secrets::Recovery.export(keypair.identity, passphrase)

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
    puts "Master key stored in Keychain (account: #{Secrets::MasterKey::KEYCHAIN_ACCOUNT})."
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
      parser.banner = "Usage: secrets vault create -n NAME [options]"
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

    keypair = Secrets::MasterKey.read
    initial = "# vault: #{name} (created #{Time.utc.to_s("%Y-%m-%d")})\n"
    ciphertext = Secrets::Vault.encrypt(initial, keypair.recipient)
    File.write(path, ciphertext)
    File.chmod(path, 0o600)
    Secrets::Audit.log(name, "create")

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
    Secrets::Audit.log(vault_name, "set", key)

    puts "set #{key} in #{vault_name}"
    0
  rescue ex
    STDERR.puts "set failed: #{ex.message}"
    1
  end

  # ====================================================================
  # delete
  # ====================================================================

  def delete_cmd(argv : Array(String)) : Int32
    vault_name, key, vault_dir = parse_vault_key_args(argv, "delete")
    return 64 if vault_name.empty? || key.empty?

    doc = read_vault(vault_name, vault_dir)
    removed = doc.delete(key)
    unless removed
      STDERR.puts "key not found: #{key}"
      return 1
    end
    write_vault(vault_name, vault_dir, doc)
    Secrets::Audit.log(vault_name, "delete", key)

    puts "deleted #{key} from #{vault_name}"
    0
  rescue ex
    STDERR.puts "delete failed: #{ex.message}"
    1
  end

  # ====================================================================
  # list
  # ====================================================================

  def list_cmd(argv : Array(String)) : Int32
    vault_name = ""
    vault_dir = DEFAULT_VAULT_DIR

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: secrets list -n VAULT [options]"
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
  # edit
  # ====================================================================

  def edit_cmd(argv : Array(String)) : Int32
    vault_name, vault_dir = parse_vault_only_args(argv, "edit")
    return 64 if vault_name.empty?

    doc = read_vault(vault_name, vault_dir)
    before = doc.to_toml
    after = Secrets::Editor.edit(before)

    if after == before
      puts "no changes, vault not touched"
      return 0
    end

    # Validate the edited buffer is still valid TOML before re-encrypting.
    begin
      ::TOML.parse(after)
    rescue ex
      STDERR.puts "edited content is not valid TOML: #{ex.message}"
      STDERR.puts "vault was NOT modified."
      return 1
    end

    keypair = Secrets::MasterKey.read
    ciphertext = Secrets::Vault.encrypt(after, keypair.recipient)
    File.write(vault_path(vault_name, vault_dir), ciphertext)
    File.chmod(vault_path(vault_name, vault_dir), 0o600)
    Secrets::Audit.log(vault_name, "edit")

    puts "edited #{vault_name}"
    0
  rescue ex
    STDERR.puts "edit failed: #{ex.message}"
    1
  end

  # ====================================================================
  # rotation
  # ====================================================================
  # Re-encrypt the vault under the current master key. Useful when the
  # ciphertext file has leaked: a fresh nonce gives a new ciphertext
  # for the same plaintext, so backups from before the rotation cannot
  # be confused with the current canonical state. (Note: an attacker
  # who already decrypted a leaked copy still has the plaintext —
  # rotation invalidates the *file*, not the secrets it held.)
  #
  # Once multi-recipients land (v0.4.0), `rotation` will also pick up
  # the latest `recipients.toml`, which is when it becomes load-bearing.

  def rotation_cmd(argv : Array(String)) : Int32
    vault_name, vault_dir = parse_vault_only_args(argv, "rotation")
    return 64 if vault_name.empty?

    doc = read_vault(vault_name, vault_dir)
    write_vault(vault_name, vault_dir, doc)
    Secrets::Audit.log(vault_name, "rotation")

    puts "rotated #{vault_name} (re-encrypted under current master key)"
    0
  rescue ex
    STDERR.puts "rotation failed: #{ex.message}"
    1
  end

  # ====================================================================
  # diff
  # ====================================================================
  # Compare the current vault plaintext to another encrypted vault
  # file (typically a previous git checkout, e.g. `git show HEAD~1:foo.toml.age`
  # piped to a tempfile). Both files must be decryptable with the
  # current master key. Output is a unified diff (`diff -u`).

  def diff_cmd(argv : Array(String)) : Int32
    vault_name = ""
    vault_dir = DEFAULT_VAULT_DIR
    against = ""

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: secrets diff -n VAULT --against PATH.age [options]"
      parser.on("-n NAME", "--name=NAME", "Current vault name") { |v| vault_name = v }
      parser.on("-a PATH", "--against=PATH", "Path to the other encrypted vault to compare against") { |v| against = v }
      parser.on("-d DIR", "--vault-dir=DIR", "Vault directory") { |v| vault_dir = v }
      parser.on("-h", "--help", "Show this help") { puts parser; exit 0 }
    end

    if vault_name.empty?
      STDERR.puts "missing -n/--name"
      return 64
    end
    if against.empty?
      STDERR.puts "missing -a/--against PATH.age"
      return 64
    end
    unless File.exists?(against)
      STDERR.puts "against file not found: #{against}"
      return 1
    end

    keypair = Secrets::MasterKey.read
    current_text = Secrets::Vault.decrypt(File.read(vault_path(vault_name, vault_dir)), keypair.identity)
    other_text = Secrets::Vault.decrypt(File.read(against), keypair.identity)

    if current_text == other_text
      puts "no differences"
      return 0
    end

    # We shell out to /usr/bin/diff because reimplementing unified-diff
    # is out of scope. Both buffers go through tempfiles mode 0600 so
    # diff(1) can mmap them; they're wiped + deleted in `ensure`.
    show_diff(against, current_text, other_text)
  rescue ex
    STDERR.puts "diff failed: #{ex.message}"
    1
  end

  private def show_diff(against_path : String, current_text : String, other_text : String) : Int32
    tmpdir = ENV["TMPDIR"]? || "/tmp"
    cur_path = File.join(tmpdir, "secrets-diff-cur-#{Random::Secure.hex(8)}.toml")
    oth_path = File.join(tmpdir, "secrets-diff-oth-#{Random::Secure.hex(8)}.toml")
    File.write(cur_path, current_text)
    File.chmod(cur_path, 0o600)
    File.write(oth_path, other_text)
    File.chmod(oth_path, 0o600)
    begin
      Process.run("diff", ["-u", oth_path, cur_path],
        output: STDOUT, error: STDERR)
      # diff(1) exits 0 (identical), 1 (differences), 2 (error).
      # We've already short-circuited the identical case; non-zero
      # here means the diff was printed and we're done.
      0
    ensure
      [cur_path, oth_path].each do |path|
        if File.exists?(path)
          begin
            File.open(path, "w") { |f| f.write(Bytes.new(File.size(path).to_i32, 0_u8)) }
          rescue
          end
          File.delete(path)
        end
      end
    end
  end

  # ====================================================================
  # log
  # ====================================================================
  # Print the audit log for a vault.

  def log_cmd(argv : Array(String)) : Int32
    vault_name, _vault_dir = parse_vault_only_args(argv, "log")
    return 64 if vault_name.empty?

    lines = Secrets::Audit.read(vault_name)
    if lines.empty?
      puts "no audit entries for #{vault_name}"
      return 0
    end
    lines.each { |line| puts line }
    0
  rescue ex
    STDERR.puts "log failed: #{ex.message}"
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
    keypair = Secrets::MasterKey.read
    print "Passphrase (hidden): "
    STDOUT.flush
    passphrase = read_secret_from_stdin
    if passphrase.nil? || passphrase.empty?
      STDERR.puts "no passphrase provided; aborting"
      return 64
    end
    paper = Secrets::Recovery.export(keypair.identity, passphrase)
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
    identity = Secrets::Recovery.import(paper, passphrase)
    keypair = Secrets::MasterKey.install!(identity)
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
      parser.banner = "Usage: secrets #{cmd} -n VAULT -k KEY [options]"
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

  # Variant for commands that take only a vault name (edit, rotation,
  # log) — no key argument.
  private def parse_vault_only_args(argv : Array(String), cmd : String) : Tuple(String, String)
    vault_name = ""
    vault_dir = DEFAULT_VAULT_DIR

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: secrets #{cmd} -n VAULT [options]"
      parser.on("-n NAME", "--name=NAME", "Vault name (e.g. prod)") { |v| vault_name = v }
      parser.on("-d DIR", "--vault-dir=DIR", "Vault directory") { |v| vault_dir = v }
      parser.on("-h", "--help", "Show this help") { puts parser; exit 0 }
    end

    if vault_name.empty? && argv.size >= 1 && !argv.first.starts_with?("-")
      vault_name = argv.first
    end

    {vault_name, vault_dir}
  end

  private def vault_path(name : String, vault_dir : String) : String
    File.join(vault_dir, "#{name}.toml.age")
  end

  private def read_vault(name : String, vault_dir : String) : ::TOML::Document
    path = vault_path(name, vault_dir)
    raise "vault not found: #{path}. Did you run `secrets vault create`?" unless File.exists?(path)
    keypair = Secrets::MasterKey.read
    ciphertext = File.read(path)
    plaintext = Secrets::Vault.decrypt(ciphertext, keypair.identity)
    ::TOML.parse(plaintext)
  end

  private def write_vault(name : String, vault_dir : String, doc : ::TOML::Document) : Nil
    path = vault_path(name, vault_dir)
    keypair = Secrets::MasterKey.read
    plaintext = doc.to_toml
    ciphertext = Secrets::Vault.encrypt(plaintext, keypair.recipient)
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
    io.puts "Usage: secrets SUBCOMMAND [options]"
    io.puts
    io.puts "Subcommands :"
    io.puts "  init,       i              Generate the master key and the recovery paper"
    io.puts "  vault,      vt   create    Create a new vault file"
    io.puts "  get,        g              Read a secret"
    io.puts "  set,        s              Write a secret (value via stdin)"
    io.puts "  delete,     rm             Delete a secret from a vault"
    io.puts "  list,       ls             List the keys of a vault"
    io.puts "  edit,       e              Open a vault in $EDITOR (decrypt → edit → re-encrypt)"
    io.puts "  rotation,   r              Re-encrypt a vault under the current master key"
    io.puts "  diff,       df             Compare a vault with another encrypted vault file"
    io.puts "  log,        l              Print the audit log of a vault"
    io.puts "  master-key, mk             Manage the master key (export/import)"
    io.puts "  version,    v              Print version"
    io.puts "  help,       h              Show this help"
    io.puts
    io.puts "Run `secrets SUBCOMMAND -h` for subcommand-specific options."
  end
end

exit Secrets::CLI.run(ARGV) if PROGRAM_NAME.includes?("secrets") || PROGRAM_NAME.includes?("cli")
