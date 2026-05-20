#!/usr/bin/env bash

set -euo pipefail

# cleanup.sh
#
# Examples:
#   ./cleanup.sh branches
#   ./cleanup.sh tags
#   ./cleanup.sh releases
#   ./cleanup.sh branches releases
#   ./cleanup.sh all
#
# Optional:
#   DEFAULT_BRANCH=develop ./cleanup.sh branches
#
# Requirements:
#   - git
#   - gh (GitHub CLI)
#   - authenticated gh: gh auth status

DEFAULT_BRANCH="${DEFAULT_BRANCH:-}"

usage() {
    echo "Usage:"
    echo "  $0 [branches] [tags] [releases] [all]"
    exit 1
}

require_repo() {
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
        echo "[!] Not inside a git repository"
        exit 1
    }
}

detect_default_branch() {
    if [[ -n "$DEFAULT_BRANCH" ]]; then
        echo "$DEFAULT_BRANCH"
        return
    fi

    local branch

    branch=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || true)

    if [[ -z "$branch" ]]; then
        if git show-ref --verify --quiet refs/heads/main; then
            branch="main"
        elif git show-ref --verify --quiet refs/heads/master; then
            branch="master"
        else
            echo "[!] Could not determine default branch"
            exit 1
        fi
    fi

    echo "$branch"
}

delete_branches() {
    local default_branch="$1"

    echo "[*] Fetching remotes..."
    git fetch --all --prune

    echo "[*] Deleting remote branches except: $default_branch"

    git branch -r \
        | grep '^  origin/' \
        | grep -vE "origin/(${default_branch}|HEAD)$" \
        | sed 's|origin/||' \
        | while read -r branch; do
            [[ -z "$branch" ]] && continue

            echo "    -> deleting remote branch: $branch"

            git push origin --delete "$branch" || true
        done

    echo "[*] Deleting local branches except: $default_branch"

    git branch \
        | sed 's/^\*//g' \
        | xargs \
        | tr ' ' '\n' \
        | grep -v "^${default_branch}$" \
        | while read -r branch; do
            [[ -z "$branch" ]] && continue

            echo "    -> deleting local branch: $branch"

            git branch -D "$branch" || true
        done
}

delete_tags() {
    echo "[*] Deleting GitHub releases first (if any use tags)..."

    gh release list --limit 1000 2>/dev/null \
        | awk '{print $1}' \
        | while read -r tag; do
            [[ -z "$tag" ]] && continue

            echo "    -> deleting release: $tag"

            gh release delete "$tag" -y || true
        done

    echo "[*] Deleting remote tags..."

    git tag -l | while read -r tag; do
        [[ -z "$tag" ]] && continue

        echo "    -> deleting remote tag: $tag"

        git push origin ":refs/tags/$tag" || true
    done

    echo "[*] Deleting local tags..."

    git tag -l | while read -r tag; do
        [[ -z "$tag" ]] && continue

        echo "    -> deleting local tag: $tag"

        git tag -d "$tag" || true
    done
}

delete_releases() {
    echo "[*] Deleting GitHub releases..."

    gh release list --limit 1000 \
        | awk '{print $1}' \
        | while read -r tag; do
            [[ -z "$tag" ]] && continue

            echo "    -> deleting release: $tag"

            gh release delete "$tag" -y || true
        done
}

main() {
    require_repo

    [[ $# -eq 0 ]] && usage

    local do_branches=0
    local do_tags=0
    local do_releases=0

    for arg in "$@"; do
        case "$arg" in
            all)
                do_branches=1
                do_tags=1
                do_releases=1
                ;;
            branches)
                do_branches=1
                ;;
            tags)
                do_tags=1
                ;;
            releases)
                do_releases=1
                ;;
            *)
                echo "[!] Unknown option: $arg"
                usage
                ;;
        esac
    done

    local default_branch
    default_branch=$(detect_default_branch)

    echo "[*] Default branch: $default_branch"
    echo

    if [[ "$do_branches" -eq 1 ]]; then
        delete_branches "$default_branch"
        echo
    fi

    if [[ "$do_releases" -eq 1 ]]; then
        delete_releases
        echo
    fi

    if [[ "$do_tags" -eq 1 ]]; then
        delete_tags
        echo
    fi

    echo "[+] Cleanup completed"
}

main "$@"
