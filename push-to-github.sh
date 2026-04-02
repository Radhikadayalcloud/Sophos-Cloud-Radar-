#!/bin/bash
# Sophos Cloud Radar - GitHub Push Script
# Usage: bash push-to-github.sh YOUR-GITHUB-USERNAME

set -e

USERNAME=${1:-"YOUR-USERNAME"}
REPO="sophos-cloud-radar"

echo ""
echo "Sophos Cloud Radar - GitHub Push"
echo "================================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "ERROR: git is not installed"
    exit 1
fi

# Check if we're already in a git repo
if git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Existing git repo found - adding files and pushing..."
    git add .
    git commit -m "Sophos Cloud Radar v2.0 - Haiku model, Jira integration, multi-tab editor, environment lock, PDF export fix"
    git push origin main
    echo ""
    echo "Pushed to: https://github.com/$USERNAME/$REPO"
else
    echo "Initialising new git repo..."
    git init
    git add .
    git commit -m "Sophos Cloud Radar v2.0 - initial commit"

    echo ""
    echo "Creating GitHub repo and pushing..."
    if command -v gh &> /dev/null; then
        gh repo create $REPO --public --push --source=.
        echo ""
        echo "Done: https://github.com/$USERNAME/$REPO"
    else
        echo ""
        echo "GitHub CLI not found. Run these commands manually:"
        echo ""
        echo "  git remote add origin https://github.com/$USERNAME/$REPO.git"
        echo "  git branch -M main"
        echo "  git push -u origin main"
        echo ""
        echo "Or create the repo at https://github.com/new first, then run the commands above."
    fi
fi
