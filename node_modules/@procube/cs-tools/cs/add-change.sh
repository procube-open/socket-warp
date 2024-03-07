#!/bin/bash
set -e

source $(dirname $0)/common.sh

if [ ! -r .changeset/pre.json ]; then
    echo "Preleaseモードに入っていません。"
    usage
    exit 1
fi
current_branch=$(git branch --show-current)
if [ "$current_branch" == "main" ]; then
  echo "このスクリプトはプルリクエスト用のブランチ内で変更ログを追加するものです。現在 main をチェックアウトしているためこのコマンドは使えません。"
  usage
  exit 1
fi
set -x
yarn changeset add
