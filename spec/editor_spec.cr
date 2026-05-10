require "./spec_helper"
require "file_utils"

# Tests for the $EDITOR helper. We replace `vi` with a tiny shell
# script that:
#   - reads the path from $1
#   - applies a configurable mutation to the file
#   - exits with a configurable code
# This lets us assert (a) the helper passes the file path correctly,
# (b) the returned content reflects what the editor wrote,
# (c) the tempfile is wiped + deleted regardless of editor exit code.

private def with_fake_editor(content_after : String? = nil, exit_code : Int32 = 0, &)
  dir = "/tmp/cs-editor-spec"
  FileUtils.mkdir_p(dir)
  bin = File.join(dir, "fake-editor")

  script = String.build do |s|
    s << "#!/bin/sh\n"
    if content_after
      escaped = content_after.gsub("'", "'\\''")
      s << "printf '%s' '" << escaped << "' > \"$1\"\n"
    end
    s << "exit " << exit_code << "\n"
  end
  File.write(bin, script)
  File.chmod(bin, 0o755)

  ENV["EDITOR"] = bin
  begin
    yield
  ensure
    ENV.delete("EDITOR")
    FileUtils.rm_rf(dir)
  end
end

describe Secrets::Editor do
  describe ".edit" do
    it "returns the buffer the editor wrote to the tempfile" do
      with_fake_editor(content_after: "EDITED CONTENT\n") do
        result = Secrets::Editor.edit("ORIGINAL CONTENT\n")
        result.should eq("EDITED CONTENT\n")
      end
    end

    it "returns the original buffer when the editor does not modify it" do
      with_fake_editor(content_after: nil, exit_code: 0) do
        original = "DATABASE_URL = \"postgres://...\"\n"
        Secrets::Editor.edit(original).should eq(original)
      end
    end

    it "raises Secrets::Error when the editor exits non-zero" do
      with_fake_editor(content_after: "should not be saved", exit_code: 2) do
        expect_raises(Secrets::Error, /editor.*exited with 2/) do
          Secrets::Editor.edit("payload")
        end
      end
    end

    it "deletes the tempfile even when the editor exits non-zero" do
      tmpdir = ENV["TMPDIR"]? || "/tmp"
      with_fake_editor(content_after: "x", exit_code: 1) do
        before = Dir.children(tmpdir).select { |f| f.starts_with?("secrets-edit-") }
        begin
          Secrets::Editor.edit("payload")
        rescue Secrets::Error
          # expected
        end
        after = Dir.children(tmpdir).select { |f| f.starts_with?("secrets-edit-") }
        after.size.should eq(before.size)
      end
    end
  end
end
