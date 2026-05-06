#!/bin/bash
# =============================================================================
# Release Script -- Test, bump, tag, publish to npm, create GitHub release
# =============================================================================
# Usage:
#   ./release.sh <new-version>    -- local mode, e.g. ./release.sh 0.9.1
#   ./release.sh                  -- CI mode (version derived from git tag)
#
# Local mode: runs from your workstation, bumps + commits + tags + pushes.
# CI mode: invoked by .github/workflows/release.yml on tag push, skips the
# bump/commit/tag/push steps (already done) and publishes with --provenance
# using NODE_AUTH_TOKEN from GitHub Actions secrets.
# If interrupted, just re-run with the same version -- each step is idempotent.
#
# Prerequisites (local):
#   - gh CLI authenticated
#   - npm authenticated (`npm login --auth-type=web` in your terminal first)
#   - clean git working tree on main, up to date with origin/main
# Prerequisites (CI): NODE_AUTH_TOKEN env, GITHUB_TOKEN env, CI=true.
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

IS_CI="${CI:-false}"
VERSION="${1:-}"

if [ -z "$VERSION" ]; then
  if [ "$IS_CI" = "true" ] && [ -n "${GITHUB_REF_NAME:-}" ]; then
    VERSION="${GITHUB_REF_NAME#v}"
    info "CI mode -- version $VERSION from tag $GITHUB_REF_NAME"
  else
    echo "Usage: ./release.sh <version>"
    echo "  e.g. ./release.sh 0.9.1"
    exit 1
  fi
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "Invalid version format: $VERSION (expected X.Y.Z)"
fi

echo -e "${CYAN}Pre-flight checks...${NC}"

command -v node >/dev/null || fail "node not installed"
command -v npm >/dev/null  || fail "npm not installed"
# gh is only required in local mode -- CI uses GITHUB_TOKEN with the gh action.
if [ "$IS_CI" != "true" ]; then
  command -v gh >/dev/null || fail "gh CLI not installed"
fi

# Branch check: in CI we are on a detached HEAD at the tag commit, which is fine.
if [ "$IS_CI" != "true" ]; then
  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
  if [ "$CURRENT_BRANCH" != "main" ]; then
    fail "Must be on main (currently on '$CURRENT_BRANCH')"
  fi
fi

CURRENT_VERSION=$(node -p "require('./package.json').version")

if [ "$CURRENT_VERSION" = "$VERSION" ]; then
  info "Resuming release v${VERSION}"
else
  info "Current version: $CURRENT_VERSION -> $VERSION"
fi

if [ "$IS_CI" != "true" ] && [ "$CURRENT_VERSION" != "$VERSION" ]; then
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

if [ "$IS_CI" = "true" ]; then
  info "CI mode -- skipping commit/tag/push (already tagged)"
else
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
fi

# Step 5: Publish to npm
# Local: WebAuthn session in ~/.npmrc, retry 3x for EOTP propagation after fresh login.
# CI:    NODE_AUTH_TOKEN automation token, no OTP, publish with --provenance for sigstore attestation.
step 5 "Publish to npm"

NPM_VERSION=$(npm view @yawlabs/ssh-mcp version 2>/dev/null || echo "")
if [ "$NPM_VERSION" = "$VERSION" ]; then
  info "Already published to npm -- skipping"
else
  if [ "$IS_CI" = "true" ]; then
    npm publish --access public --provenance
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

# Provenance attestation -- npm attaches sigstore attestations when
# `npm publish --provenance` runs inside GitHub Actions (the CI path).
# Missing attestation in CI means something regressed; in local mode it is expected.
if [ "$IS_CI" = "true" ]; then
  ATTEST=$(npm view "@yawlabs/ssh-mcp@${VERSION}" dist.attestations.provenance.predicateType 2>/dev/null || echo "")
  if [ -n "$ATTEST" ]; then
    info "provenance attestation: $ATTEST"
  else
    warn "no provenance attestation found on v${VERSION} (expected in CI publish)"
  fi
fi

echo ""
echo -e "${GREEN}v${VERSION} released successfully!${NC}"
echo -e "${GREEN}  install: npm i @yawlabs/ssh-mcp@${VERSION}${NC}"
echo ""
