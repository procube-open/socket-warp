# socket-warp
以下cargoが導入されていることを前提としている。

## 接続手順
```
cd fc_server
cargo run
```
でサーバを起動し、
```
cd fc_agent
cargo run
```
でサーバに接続できる。

## 証明書作成
ルートに`Certs_and_Key`ディレクトリを作成し、その中にDER形式の各種証明書ファイルを入れる必要がある。