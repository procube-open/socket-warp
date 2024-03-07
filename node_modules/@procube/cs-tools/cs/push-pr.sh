#!/bin/bash
set -e

source $(dirname $0)/common.sh

if git remote | grep -q 'upstream'; then
  remote=upstream
else
  remote=origin
fi

if [ ! -r .changeset/pre.json ]; then
    echo "Preleaseモードに入っていません。"
    usage
    exit 1
fi
current_branch=$(git branch --show-current)
if [ "$current_branch" == "main" ]; then
  echo "このスクリプトはプルリクエスト用のブランチでリモートにプッシュするものです。現在 main をチェックアウトしているためこのコマンドは使えません。"
  usage
  exit 1
fi
set -x
yarn changeset status
yarn changeset version
version=$(node -e "console.log(require('./package.json').version)")
git add -A
git commit -m "commit for $version"
git tag "v${version}"
git push $remote $current_branch
set +x
pr_url=$(gh pr status --jq .currentBranch.url --json url)
if [ -n "$pr_url" ]; then
  echo "プルリクエストは作成済みです。"
  exit 0
fi
set -x
gh pr create -B main -H "${current_branch}" --title "${current_branch}" --body 'Created by tools for changesets'
