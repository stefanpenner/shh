#!/bin/sh
# Build the iOS vault framework from shhcore. The main module stays free of gomobile.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ -x /usr/local/go/bin/go ]; then
  PATH="/usr/local/go/bin:$PATH"
fi
export GOTOOLCHAIN=go1.25.0
export PATH="$(go env GOPATH)/bin:$PATH"
if ! command -v gomobile >/dev/null 2>&1; then
  go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260821151724-5c0595f4cdbb
  go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260821151724-5c0595f4cdbb
fi
cd "$root/ios/bind"
gomobile bind -target ios -o "$root/ios/ShhCore.xcframework" github.com/stefanpenner/shh/shhcore
