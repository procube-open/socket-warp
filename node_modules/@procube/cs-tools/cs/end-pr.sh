#!/bin/bash
set -e

source $(dirname $0)/common.sh

do_merge="yes"
if [ $# -gt 0 ]; then
  if [ "$1" == "--no-merge" ]; then
    do_merge="no"
    shift
  fi
fi
if [ $# -gt 0 ]; then
  echo "$1 は指定できません"
  exit 1
fi

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
  echo "このスクリプトはプルリクエスト用のブランチから初めてプルリクエストを終了するものです。現在 main をチェックアウトしているためこのコマンドは使えません。"
  usage
  exit 1
fi
set -x
yarn changeset pre exit
yarn changeset version
set +x
version=$(node -e "console.log(require('./package.json').version)")
set -x
git add -A
git commit -m "commit for $version"
git push $remote $current_branch
pr_url=$(gh pr status --jq .currentBranch.url --json url)
if [ -z "$pr_url" ]; then
  echo "プリリクエストが作成されていません。"
  exit 1
fi
set +x
if [ "$do_merge" == "no" ]; then
  exit 0
fi
sleep 2
set -x
# gh pr review "$pr_url" --approve
gh pr merge --auto --delete-branch --squash "$pr_url"
git fetch $remote --prune
if [ $remote == 'upstream' ]; then
  git push origin main
fi
