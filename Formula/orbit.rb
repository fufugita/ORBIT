class Orbit < Formula
  desc "Customizable terminal and browser agent harness"
  homepage "https://github.com/fufugita/ORBIT"
  license "Apache-2.0"
  head "https://github.com/fufugita/ORBIT.git", branch: "main"

  depends_on :linux
  depends_on "rust" => :build

  def fetch
    system "cargo", "fetch", *std_cargo_fetch_args
  end

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/cli")
    system "cargo", "install", *std_cargo_args(path: "crates/web")

    doc.install "LICENSE", "README.md", "docs/setup.md", "docs/customization.md",
                "docs/pentest.md", "docs/integrations.md", "docs/browser-harness.md"
  end

  test do
    assert_match "orbit ", shell_output("#{bin}/orbit --version")

    home = testpath/"orbit-home"
    setup = JSON.parse(shell_output("#{bin}/orbit --home #{home} setup --no-provider --json"))
    assert_equal "ok", setup.fetch("status")
    assert_equal true, setup.fetch("offline")
    assert_path_exists home/"trust/operator.key"

    doctor = JSON.parse(shell_output("#{bin}/orbit --home #{home} doctor --json", 1))
    assert_equal "doctor", doctor.fetch("command")
    assert_equal false, doctor.fetch("report").fetch("ready")
    identity = doctor.fetch("report").fetch("checks").find { |check| check.fetch("id") == "identity" }
    assert_equal "ready", identity.fetch("status")
    providers = doctor.fetch("report").fetch("checks").find { |check| check.fetch("id") == "providers" }
    assert_equal "missing", providers.fetch("status")

    assert_match "not initialized",
                 shell_output("#{bin}/orbit-web --home #{testpath}/uninitialized --no-browser 2>&1", 2)
  end
end
