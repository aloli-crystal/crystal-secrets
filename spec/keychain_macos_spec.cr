require "./spec_helper"
require "file_utils"

# Tests for the Keychain backend, replacing /usr/bin/security with a
# fake shell script that records every invocation (args + stdin) into
# a log file the test then inspects. Lets us assert :
#  - the secret never appears in argv
#  - the right subcommand is invoked
#  - exit code drives KeychainError correctly

# Stateful fake: stores entries on disk under a per-service file so
# find/store/delete reflect actual state. Required to test migration
# sequences whose later results depend on earlier ones.
private def with_stateful_security(preset : Hash(String, String) = {} of String => String, &)
  base = "/tmp/cs-keychain-stateful"
  state = "#{base}/state"
  bin = "#{base}/security"
  FileUtils.rm_rf(base)
  Dir.mkdir_p(state)

  preset.each do |service_account, value|
    File.write(File.join(state, service_account), value)
  end

  script = <<-SH
  #!/bin/sh
  STATE="#{state}"
  mode=""
  service=""
  account=""
  value=""
  while [ $# -gt 0 ]; do
    case "$1" in
      add-generic-password)    mode=add;    shift ;;
      find-generic-password)   mode=find;   shift ;;
      delete-generic-password) mode=delete; shift ;;
      -s) service="$2"; shift; [ $# -gt 0 ] && shift ;;
      -a) account="$2"; shift; [ $# -gt 0 ] && shift ;;
      # `find-generic-password ... -w` passe `-w` SEUL en dernier arg
      # (sémantique réelle : « n'imprimer que le mot de passe »). Un
      # `shift 2` quand il ne reste qu'un seul arg échoue SANS décrémenter
      # $# -> boucle `while [ $# -gt 0 ]` infinie = hang de la CI. On
      # shift 1 pour `-w`, puis 1 de plus seulement s'il reste une valeur
      # (cas `add-generic-password ... -w <value> -U`).
      -w) value="$2"; shift; [ $# -gt 0 ] && shift ;;
      *)  shift ;;
    esac
  done
  key="$STATE/${service}__${account}"
  case "$mode" in
    add)    printf '%s' "$value" > "$key"; exit 0 ;;
    find)   [ -f "$key" ] && cat "$key" && exit 0; exit 44 ;;
    delete) rm -f "$key"; exit 0 ;;
  esac
  exit 1
  SH
  File.write(bin, script)
  File.chmod(bin, 0o755)

  ENV["SECURITY_BIN"] = bin
  begin
    yield state
  ensure
    ENV.delete("SECURITY_BIN")
    FileUtils.rm_rf(base)
  end
end

private def with_fake_security(behaviour : String? = nil, &)
  Dir.mkdir_p("/tmp/cs-keychain-test")
  log = "/tmp/cs-keychain-test/calls.log"
  bin = "/tmp/cs-keychain-test/security"
  File.delete(log) if File.exists?(log)

  script = String.build do |s|
    # On ne lit JAMAIS stdin ici : `security` ne prend pas le secret sur
    # stdin (cf. backend), donc aucun test n'asserte plus `STDIN:`. Un
    # `stdin=$(cat)` bloquerait le faux process tant que stdin n'est pas
    # fermé — ce qui figeait la CI (fetch/exists/delete ne ferment pas
    # stdin). On se contente de logguer la ligne de commande (`CMD:`).
    s << <<-SH
    #!/bin/sh
    LOG="#{log}"
    {
      printf 'CMD:'
      for a in "$@"; do printf ' %s' "$a"; done
      printf '\\n'
    } >> "$LOG"
    SH
    if behaviour
      s << "\n" << behaviour << "\n"
    else
      s << "\nexit 0\n"
    end
  end
  File.write(bin, script)
  File.chmod(bin, 0o755)

  ENV["SECURITY_BIN"] = bin
  begin
    yield log
  ensure
    ENV.delete("SECURITY_BIN")
    FileUtils.rm_rf("/tmp/cs-keychain-test")
  end
end

describe Secrets::KeychainMacOS do
  describe ".store" do
    it "calls add-generic-password avec la valeur via -w (argv), service, account, update" do
      with_fake_security do |log|
        Secrets::KeychainMacOS.store("master-key", "AGE-SECRET-KEY-1ABC")
        recorded = File.read(log)
        recorded.should contain("add-generic-password")
        recorded.should contain("-a master-key")
        recorded.should contain("-s dev.aloli.secrets")
        recorded.should contain("-U")
        # `security add-generic-password` n'a pas de mode stdin : la
        # valeur passe par `-w <value>`. Régression du bug « -w - » qui
        # stockait le littéral « - » : on exige la vraie valeur, pas un tiret.
        recorded.should contain("-w AGE-SECRET-KEY-1ABC")
        recorded.should_not contain("-w -\n")
      end
    end

    it "round-trip store→fetch rend la valeur EXACTE (aurait attrapé le bug -w -)" do
      with_stateful_security do
        Secrets::KeychainMacOS.store("master-key", "AGE-SECRET-KEY-1ROUNDTRIP")
        Secrets::KeychainMacOS.fetch("master-key").should eq("AGE-SECRET-KEY-1ROUNDTRIP")
      end
    end

    it "raises KeychainError when security exits non-zero" do
      with_fake_security(behaviour: "exit 1") do
        expect_raises(Secrets::KeychainError, /failed/) do
          Secrets::KeychainMacOS.store("master-key", "x")
        end
      end
    end
  end

  describe ".fetch" do
    it "returns the value from stdout (chomped)" do
      with_fake_security(behaviour: "echo 'AGE-SECRET-KEY-1xyz'") do
        Secrets::KeychainMacOS.fetch("master-key").should eq("AGE-SECRET-KEY-1xyz")
      end
    end

    it "raises KeychainError when entry not found (exit 44)" do
      with_fake_security(behaviour: "exit 44") do
        expect_raises(Secrets::KeychainError, /not found/) do
          Secrets::KeychainMacOS.fetch("master-key")
        end
      end
    end
  end

  describe ".exists?" do
    it "returns true on success" do
      with_fake_security do
        Secrets::KeychainMacOS.exists?("master-key").should be_true
      end
    end

    it "returns false on failure" do
      with_fake_security(behaviour: "exit 44") do
        Secrets::KeychainMacOS.exists?("master-key").should be_false
      end
    end
  end

  describe ".delete" do
    it "calls delete-generic-password and ignores absent entries" do
      with_fake_security do |log|
        Secrets::KeychainMacOS.delete("master-key")
        File.read(log).should contain("delete-generic-password")
      end
    end
  end

  describe ".migrate_legacy_if_needed!" do
    it "is a no-op when no entry exists anywhere" do
      with_stateful_security do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_false
        Dir.children(state).should be_empty
      end
    end

    it "is a no-op when only the new entry exists" do
      preset = {"dev.aloli.secrets__master-key" => "AGE-SECRET-KEY-1NEW"}
      with_stateful_security(preset: preset) do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_false
        File.exists?(File.join(state, "dev.aloli.secrets__master-key")).should be_true
        File.exists?(File.join(state, "dev.aloli.crystal-secrets__master-key")).should be_false
      end
    end

    it "copies a legacy-only entry to the new service and deletes the legacy one" do
      preset = {"dev.aloli.crystal-secrets__master-key" => "AGE-SECRET-KEY-1LEGACY"}
      with_stateful_security(preset: preset) do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_true
        File.read(File.join(state, "dev.aloli.secrets__master-key")).should eq("AGE-SECRET-KEY-1LEGACY")
        File.exists?(File.join(state, "dev.aloli.crystal-secrets__master-key")).should be_false
      end
    end

    it "leaves the new entry untouched if both exist (= legacy obsolete)" do
      preset = {
        "dev.aloli.crystal-secrets__master-key" => "AGE-SECRET-KEY-1OLD",
        "dev.aloli.secrets__master-key"         => "AGE-SECRET-KEY-1AUTHORITATIVE",
      }
      with_stateful_security(preset: preset) do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_false
        File.read(File.join(state, "dev.aloli.secrets__master-key"))
          .should eq("AGE-SECRET-KEY-1AUTHORITATIVE")
        # The legacy entry remains: not our job to clean it up if the
        # user explicitly created the new one in parallel.
        File.exists?(File.join(state, "dev.aloli.crystal-secrets__master-key")).should be_true
      end
    end
  end
end
