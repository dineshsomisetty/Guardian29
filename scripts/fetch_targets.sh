#!/usr/bin/env bash
# Fetch the reproducible Juice Shop demo target used by Guardian.
#
# The target is intentionally pinned to a commit, rather than a branch or tag.
# To update it, change this script and docs/targets.md together, then re-verify
# every fact in GUARDIAN_PLAN.md section 10.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly JUICE_SHOP_URL="https://github.com/juice-shop/juice-shop.git"
readonly JUICE_SHOP_COMMIT="c9f99228d9d56afb5f5ca7925376292f7fa44b13"
readonly JUICE_SHOP_DIR="${REPO_ROOT}/targets/juice-shop"

if [[ -e "${JUICE_SHOP_DIR}" ]]; then
  if [[ ! -d "${JUICE_SHOP_DIR}/.git" ]]; then
    printf 'Refusing to replace non-git target directory: %s\n' "${JUICE_SHOP_DIR}" >&2
    exit 1
  fi

  current_commit="$(git -C "${JUICE_SHOP_DIR}" rev-parse HEAD)"
  if [[ "${current_commit}" == "${JUICE_SHOP_COMMIT}" ]]; then
    printf 'Juice Shop already present at pinned commit %s\n' "${JUICE_SHOP_COMMIT}"
    exit 0
  fi

  printf 'Refusing to replace existing Juice Shop checkout at %s.\n' "${current_commit}" >&2
  printf 'Expected pinned commit: %s\n' "${JUICE_SHOP_COMMIT}" >&2
  printf 'Move the directory aside after reviewing it, then rerun this script.\n' >&2
  exit 1
fi

mkdir -p "${REPO_ROOT}/targets"
git clone --no-checkout "${JUICE_SHOP_URL}" "${JUICE_SHOP_DIR}"
git -C "${JUICE_SHOP_DIR}" checkout --detach "${JUICE_SHOP_COMMIT}"

checked_out_commit="$(git -C "${JUICE_SHOP_DIR}" rev-parse HEAD)"
if [[ "${checked_out_commit}" != "${JUICE_SHOP_COMMIT}" ]]; then
  printf 'Checkout did not resolve to the expected commit.\n' >&2
  exit 1
fi

if [[ -n "$(git -C "${JUICE_SHOP_DIR}" status --porcelain)" ]]; then
  printf 'Pinned target checkout is unexpectedly dirty: %s\n' "${JUICE_SHOP_DIR}" >&2
  exit 1
fi

printf 'Fetched Juice Shop at pinned commit %s\n' "${checked_out_commit}"
