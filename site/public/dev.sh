#!/usr/bin/env bash
# decomp.wtf's dev branch, for testing what isn't released yet (Linux):
#
#   curl -fsSL https://decomp.wtf/dev.sh | bash
#
# Runs the dev branch's own installer (install.sh on GitHub) with DECOMP_BRANCH=dev: decomp.wtf installs from the
# branch's newest commit, and the app then offers every new commit pushed there as an update (one click).
# Back to releases: curl -fsSL https://decomp.wtf/install.sh | bash
set -euo pipefail
BRANCH="${DECOMP_BRANCH:-dev}"
curl -fsSL "https://raw.githubusercontent.com/giveen/decomp.anything/$BRANCH/site/public/install.sh" | DECOMP_BRANCH="$BRANCH" bash -s -- "$@"
