#!/usr/bin/env sh
# Builds dist/openback-app-auth-joomla-1.0.0.zip. Options are passed to build.php (e.g. --sync).
set -eu
cd "$(dirname "$0")"
exec php build.php "$@"
