#!/bin/sh
# First process of an eVal terminal session. eVal copies in:
#   /workspace   the audited commit (no .git: eVal never copies repository credentials or remote config)
#   /eval/fix    the fix's files, at their repository paths
#   /eval/motd   the session banner; /eval/commit the audited commit SHA
# This script commits the audited tree to a local git repository and then applies the fix on top, so
# `git diff` shows exactly the fix. Then it hands the terminal to bash.
set -e
cd /workspace
if [ ! -d .git ]; then
  git init -q -b audited
  git -c user.name=eVal -c user.email=sandbox@eval.invalid add -A
  git -c user.name=eVal -c user.email=sandbox@eval.invalid commit -q --allow-empty \
    -m "Audited commit $(cat /eval/commit 2>/dev/null || echo unknown)"
  if [ -d /eval/fix ]; then cp -a /eval/fix/. /workspace/; fi
fi
[ -f /eval/motd ] && cat /eval/motd
exec bash -l
