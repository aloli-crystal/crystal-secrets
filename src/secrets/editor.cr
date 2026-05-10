require "process"
require "file_utils"
require "random/secure"
require "./error"

module Secrets
  # `secrets edit` helper: write `plaintext` to a mode-0600 tempfile,
  # spawn `$EDITOR` (default `vi`) on it, return the edited buffer.
  # The tempfile is wiped (best-effort) and deleted in `ensure`,
  # whether the editor succeeded or not.
  #
  # Why not stream through the editor? Most editors don't accept
  # stdin/stdout for buffer editing — they need a file path. The
  # tempfile is on /tmp (or `$TMPDIR`) for the duration of the edit,
  # mode 0600 so other users on the box can't peek.
  module Editor
    extend self

    def default_editor : String
      ENV["EDITOR"]? || ENV["VISUAL"]? || "vi"
    end

    def tmpdir : String
      ENV["TMPDIR"]? || "/tmp"
    end

    # Open `plaintext` in `$EDITOR`, return what the user wrote.
    # Raises `Secrets::Error` if the editor exits non-zero (the
    # caller treats this as "user aborted, do not save").
    def edit(plaintext : String, suffix : String = ".toml") : String
      path = File.join(tmpdir, "secrets-edit-#{Random::Secure.hex(8)}#{suffix}")
      File.write(path, plaintext)
      File.chmod(path, 0o600)
      begin
        status = Process.run(
          default_editor,
          [path],
          input: Process::Redirect::Inherit,
          output: Process::Redirect::Inherit,
          error: Process::Redirect::Inherit,
        )
        raise Error.new("editor #{default_editor} exited with #{status.exit_code}, vault not modified") unless status.success?
        File.read(path)
      ensure
        if File.exists?(path)
          # Best-effort wipe before delete: overwrite with zeros, the
          # plaintext can include secrets the user just typed in.
          begin
            current = File.size(path)
            File.open(path, "w") { |f| f.write(Bytes.new(current.to_i32, 0_u8)) }
          rescue
            # ignore — we still try to delete
          end
          File.delete(path)
        end
      end
    end
  end
end
