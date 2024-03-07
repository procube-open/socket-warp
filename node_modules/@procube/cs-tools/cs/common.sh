# このファイルは source で他のシェルから読み込まれることが前提となっています。
if [ -r .env ]; then
  export $(cat .env | grep -v ^#)
fi

function usage() {
    echo "以下の手順でご利用ください。"
    echo " 1. yarn start-pr でプルリクエスト用ブランチを作成し、 Prerelease モードに入る"
    echo " 2. yarn add-change で変更内容ログを追加する"
    echo " 3. yarn push-pr でその内容を github.com にプッシュする"
    echo " 4. yarn end-pr で Prerelease モードを終了し、マージし、 main ブランチに戻り、 pull し、プルリクエスト用ブランチを削除する"
}

if ! git_status=$(git status); then
    echo "git リポジトリに異常があるようです。"
    echo "$git_status"
    exit 1
fi

if ! gh_auth_status=$(gh auth status 2>&1) || [[ "$gh_auth_status" =~ 'Failed to log in to' ]]; then
    echo "Github CLI でログインできていないようです。"
    echo "$gh_auth_status"
    if [ -z "$GH_TOKEN" ]; then
        echo "環境変数 GH_TOKEN にパーソナルアクセストークンを設定して利用してください"
        echo ".env に GH_TOKEN=XXX という形式で設定されていれば自動的に読み込まれます。"
    fi
    exit 1
fi
