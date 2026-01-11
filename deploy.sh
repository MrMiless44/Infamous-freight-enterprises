#!/usr/bin/env bash
set -euo pipefail

# Deploy current directory to gh-pages using git worktree.
# Requirements: a git repository with an 'origin' remote.

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RESET="\033[0m"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo -e "${RED}Error:${RESET} Not inside a git repository." >&2
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo -e "${RED}Error:${RESET} No 'origin' remote configured." >&2
  exit 1
fi

BRANCH=gh-pages
WORKTREE_DIR=gh-pages

# Ensure branch exists remotely
if ! git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  echo -e "${YELLOW}Creating remote branch '${BRANCH}'...${RESET}"
  git push origin "$(git commit-tree $(git hash-object -t tree /dev/null) -m 'Initial gh-pages')":refs/heads/"$BRANCH"
fi

# Clean existing worktree if present
if [ -d "$WORKTREE_DIR" ]; then
  echo -e "${YELLOW}Removing existing worktree '${WORKTREE_DIR}'...${RESET}"
  git worktree remove --force "$WORKTREE_DIR" || true
fi

# Add worktree
echo -e "${GREEN}Adding worktree for '${BRANCH}'...${RESET}"
git fetch origin "$BRANCH"
git worktree add -f "$WORKTREE_DIR" origin/"$BRANCH"

# Sync files
echo -e "${GREEN}Copying site files...${RESET}"
rsync -av --delete --exclude "$WORKTREE_DIR" --exclude ".git" ./ "$WORKTREE_DIR"/

pushd "$WORKTREE_DIR" >/dev/null
  echo -e "${GREEN}Committing and pushing...${RESET}"
  git add -A
  if git diff --cached --quiet; then
    echo -e "${YELLOW}No changes to deploy.${RESET}"
  else
    git commit -m "Deploy $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    git push origin HEAD:"$BRANCH"
    echo -e "${GREEN}Deployed to '${BRANCH}'.${RESET}"
  fi
popd >/dev/null

# Cleanup
git worktree remove --force "$WORKTREE_DIR" || true
