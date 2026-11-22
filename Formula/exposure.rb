# The Homebrew formula for exposure. It builds the scanner from source, from
# the latest release tag of this repository, which is its own tap:
#
#   brew tap Adityaakr/exposure-scanner https://github.com/Adityaakr/exposure-scanner
#   brew install exposure
#
# A release changes `tag` and `revision` below (the full commit the tag
# points at, so a moved tag fails the install), and `brew upgrade` sees it.
# `brew install --HEAD exposure` builds the latest commit on main instead.
class Exposure < Formula
  desc "Show which companies' SDKs your apps ship, with the evidence for each"
  homepage "https://github.com/Adityaakr/exposure-scanner"
  url "https://github.com/Adityaakr/exposure-scanner.git",
      tag:      "v0.2.0",
      revision: "517b72ab111f21b06523f323ec3053416b86a5c4"
  # The code, and the rule pack compiled into the binary.
  license all_of: ["Apache-2.0", "CC-BY-4.0"]
  head "https://github.com/Adityaakr/exposure-scanner.git", branch: "main"

  depends_on "rust" => :build

  def install
    # `--locked`, from std_cargo_args, builds with the dependency versions
    # the project tests.
    system "cargo", "install", *std_cargo_args(path: "crates/xs-cli")
  end

  test do
    assert_equal "exposure #{version}\n", shell_output("#{bin}/exposure --version")
    # The rule pack compiled into the binary passes its signature check.
    assert_match(/^\d+ rules$/, shell_output("#{bin}/exposure rules show"))
    (testpath/"apps").mkpath
    report = shell_output("#{bin}/exposure scan --no-cache --json - #{testpath}/apps")
    assert_match "\"schema\":\"exposure-report/1\"", report
  end
end
