#!/bin/bash
set -e

source $(dirname $0)/common.sh

if git remote | grep -q 'upstream'; then
  remote=upstream
else
  remote=origin
fi

if [ -r .changeset/pre.json ]; then
    echo "Preleaseモードに入っています。"
    usage
    exit 1
fi
current_branch=$(git branch --show-current)
if [ "$current_branch" != "main" ]; then
  echo "このスクリプトは main ブランチから新しくプルリクエスト用のブランチを作成するものです。現在 ${current_branch} をチェックアウトしているためこのコマンドは使えません。"
  usage
  exit 1
fi
branch_name=${1:-$(date +pr-%y%m%d%H%M%S)}
echo "${remote}/main ブランチを pull します。"
if ! git pull $remote main; then
  echo "${remote}/main ブランチの pull に失敗しました。 git コマンドのメッセージに従って解消してください。"
  exit 1
fi
set -x
git checkout -b ${branch_name}
yarn changeset pre enter rc
