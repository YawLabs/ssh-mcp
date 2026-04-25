#!/bin/bash
# =============================================================================
# Release Script -- Test, bump, tag, publish to npm, create GitHub release
# =============================================================================
# Usage:
#   ./release.sh <new-version>    e.g. ./release.sh 0.9.0
#
# Local-only: this repo does not run CI. Run from your workstation.
# If interrupted, just re-run with the same version -- each step is idempotent.
#
# Prerequisites:
#   - gh CLI authenticated
#   - npm authenticated (`npm login --auth-type=web` in your terminal first)
#   - clean git working tree on main, up to date with origin/main
# =============================================================================

set -euo pipefail
trap 'echo -e "\n\033[0;31m  x Release failed at line $LINENO (exit code $?)\033[0m"' ERR

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== [$1/$TOTAL_STEPS] $2 ===${NC}"; }
info() { echo -e "${GREEN}  + $1${NC}"; }
warn() { echo -e "${YELLOW}  ! $1${NC}"; }
fail() { echo -e "${RED}  x $1${NC}"; exit 1; }

TOTAL_STEPS=7

if [ $# -lt 1 ]; then
  echo "Usage: ./release.sh <version>"
  echo "  e.g. ./release.sh 0.9.0"
  exit 1
fi
VERSION="$1"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "Invalid version format: $VERSION (expected X.Y.Z)"
fi

echo -e "${CYAN}Pre-flight checks...${NC}"

command -v gh >/dev/null   || fail "gh CLI not installed"
command -v node >/dev/null || fail "node not installed"
command -v npm >/dev/null  || fail "npm not installed"

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
  fail "Must be on main (currently on '$CURRENT_BRANCH')"
fi

CURRENT_VERSION=$(node -p "require('./package.json').version")

if [ "$CURRENT_VERSION" = "$VERSION" ]; then
  info "Resuming release v${VERSION}"
else
  info "Current version: $CURRENT_VERSION -> $VERSION"
fi

if [ "$CURRENT_VERSION" != "$VERSION" ]; then
  echo ""
  echo -e "${YELLOW}About to release v${VERSION}. This will:${NC}"
  echo "  1. Run lint, typecheck, build, tests"
  echo "  2. Bump version in package.json"
  echo "  3. Commit, tag, and push"
  echo "  4. Publish to npm"
  echo "  5. Create GitHub release"
  echo ""
  read -p "Continue? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
fi

# Step 1: Lint, typecheck, build, test
step 1 "Lint, typecheck, build, test"

npm run lint || fail "Lint failed (run 'npm run lint:fix')"
npm run typecheck || fail "Type check failed"
npm run build || fail "Build failed"
npm test || fail "Tests failed"
info "All checks passed"

# Step 2: Bump version
step 2 "Bump version to $VERSION"

if [ "$CURRENT_VERSION" = "$VERSION" ]; then
  info "Already at v${VERSION} -- skipping"
else
  npm version "$VERSION" --no-git-tag-version
  info "package.json updated"
fi

# Step 3: Commit and tag
step 3 "Commit and tag"

if [ -n "$(git status --porcelain package.json package-lock.json 2>/dev/null)" ]; then
  git add package.json package-lock.json
  git commit -m "v${VERSION}"
  info "Committed version bump"
else
  info "Already committed -- skipping"
fi

if git tag -l "v${VERSION}" | grep -q "v${VERSION}"; then
  info "Tag v${VERSION} already exists -- skipping"
else
  git tag "v${VERSION}"
  info "Tag v${VERSION} created"
fi

# Step 4: Push
step 4 "Push to origin"

git push origin main --tags
info "Pushed commit and tag"

# Step 5: Publish to npm (with EOTP retry for fresh WebAuthn sessions)
step 5 "Publish to npm"

NPM_VERSION=$(npm view @yawlabs/ssh-mcp version 2>/dev/null || echo "")
if [ "$NPM_VERSION" = "$VERSION" ]; then
  info "Already published to npm -- skipping"
else
  PUBLISHED=0
  for attempt in 1 2 3; do
    if npm publish --access public; then
      PUBLISHED=1
      break
    fi
    if [ $attempt -lt 3 ]; then
      warn "Publish attempt $attempt failed (often EOTP from a fresh npm login). Retrying in 30s..."
      sleep 30
    fi
  done
  if [ $PUBLISHED -ne 1 ]; then
    fail "npm publish failed after 3 attempts"
  fi
  info "Published @yawlabs/ssh-mcp@${VERSION} to npm"
fi

# Step 6: Create GitHub release
step 6 "Create GitHub release"

if gh release view "v${VERSION}" >/dev/null 2>&1; then
  info "GitHub release v${VERSION} already exists -- skipping"
else
  PREV_TAG=$(git tag --sort=-v:refname | grep -A1 "^v${VERSION}$" | tail -1)
  if [ -n "$PREV_TAG" ] && [ "$PREV_TAG" != "v${VERSION}" ]; then
    CHANGELOG=$(git log --oneline "${PREV_TAG}..v${VERSION}" --no-decorate | sed 's/^[a-f0-9]* /- /')
  else
    CHANGELOG="Initial release"
  fi

  gh release create "v${VERSION}" \
    --title "v${VERSION}" \
    --notes "$CHANGELOG"
  info "GitHub release created"
fi

# Step 7: Verify
step 7 "Verify"

sleep 3

LIVE_VERSION=$(npm view @yawlabs/ssh-mcp version 2>/dev/null || echo "")
if [ "$LIVE_VERSION" = "$VERSION" ]; then
  info "npm: @yawlabs/ssh-mcp@${LIVE_VERSION}"
else
  warn "npm: ${LIVE_VERSION} (expected ${VERSION} -- may still be propagating)"
fi

GH_TAG=$(gh release view "v${VERSION}" --json tagName --jq '.tagName' 2>/dev/null || echo "")
if [ "$GH_TAG" = "v${VERSION}" ]; then
  info "GitHub release: ${GH_TAG}"
else
  warn "GitHub release: not found"
fi

echo ""
echo -e "${GREEN}v${VERSION} released successfully!${NC}"
echo -e "${GREEN}  install: npm i @yawlabs/ssh-mcp@${VERSION}${NC}"
echo ""
