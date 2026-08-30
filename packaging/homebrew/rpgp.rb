# Homebrew cask for rPGP.
#
# This file belongs in a tap repository — github.com/jzbz/homebrew-rpgp, at
# Casks/rpgp.rb — not here. It is kept in-tree so it versions with the thing it
# describes, and so the release process has one place to update.
#
#   brew install --cask jzbz/rpgp/rpgp
#
# A tap rather than homebrew-cask because homebrew-cask applies a notability
# bar, and at 3x for a self-submission that is 225 stars, 90 forks or 90
# watchers, plus a 30-day repository age. A tap has none of that. What a tap
# does NOT escape is Gatekeeper: brew applies com.apple.quarantine on install
# whatever tap a cask came from, --no-quarantine was removed in Homebrew 4.7,
# and the `quarantine` stanza no longer exists in the DSL. So the notarised
# zip is what makes this work — an unsigned one would install and then refuse
# to open, which is worse than not offering it.
cask "rpgp" do
  version "0.1.2"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/jzbz/rpgp/releases/download/v#{version}/rpgp-v#{version}-macos-universal.zip",
      verified: "github.com/jzbz/rpgp/"
  name "rPGP"
  desc "Manage OpenPGP certificates and keys"
  homepage "https://rpgp.app/"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :big_sur"

  app "rPGP.app"

  # Deliberately narrow. `brew uninstall --zap` is meant to remove everything an
  # app leaves behind, and the honest list here would include the secret key
  # store — which is the one directory whose loss cannot be undone. A user
  # reaching for --zap to clean up after trying an app is not asking to destroy
  # their keys, so the keys are not listed, and the uninstall message says where
  # they are instead.
  #
  # ~/Library/Application Support/rpgp/  holds secret keys and revocation
  # certificates. Removing it is a decision for the person, not for a package
  # manager flag.
  zap trash: [
    "~/Library/Saved Application State/app.rpgp.rpgp.savedState",
  ]

  caveats <<~EOS
    Your keys live in ~/Library/Application Support/rpgp/ and the certificate
    store in ~/Library/Application Support/pgp.cert.d/. Neither is removed by
    `brew uninstall`, including with --zap: losing a secret key is permanent,
    so deleting them is left to you.
  EOS
end
