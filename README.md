# socket-warp

このレポジトリでは、内向き通信が制限された環境で TCP 接続を受け付けているインタフェースに対して、QUIC 接続を用いた安全な TCP 接続を可能とするシステムを提供します。
また、mTLS に用いるクライアント/サーバ証明書の発行と検証には[procube-open/scep](https://github.com/procube-open/scep)の利用を前提としています。

## バージョン

```
cargo 1.76.0 (c84b36747 2024-01-18)
Docker version 25.0.3, build 4debf41
```

## 構成

socket-warp を構成する概念について記述します。以下は概略図です。
![概略図](/images/socket-warp.png)

赤矢印が TCP Socket であり、これがワープするような振る舞いをします。

### sw-listener と sw-connector

socket-warp は以下の二つの要素により構成されています。

- **socket-warp-listener**: QUIC 接続と API を受け付けている(以下 sw-listener)
- **socket-warp-connector**: クライアント証明書を用いて sw-listener に QUIC 接続する(以下 sw-connector)

接続を受け付けたい環境に sw-listener を置き、接続したいインタフェースが存在する環境に sw-connector を置いて下さい。

### 接続の割り振り

sw-connector が sw-listener に QUIC で接続すると、sw-listener は sw-connector のクライアント証明書に対して SCEP サーバの検証を行い、検証を通過すればその接続に対してクライアントの UID を結びつけます。

#### 補足

同一の UID を持つクライアントで複数の QUIC 接続はできないことに注意して下さい。2 点の sw-connector から同じクライアント証明書を使った場合などは、後から接続した方はエラーとなり接続することができません。

また、sw-listener の keep-alive 周期は 50 秒となっています。なので、sw-listener が sw-connector の切断に気づくまでに最大で 1 分ほどかかります。

### ポート開設

sw-listener は API によるポート開設要求を受け付けており、接続に割り振られた UID 、開設するポート、接続先のアドレスとポートを指定することで TCP 接続を受け付けるようになります。

## サンプル

socket-warp システムの構築例を記述します。以下では sw-listener が`hostname.example.com`という DNS を持つことを想定しています。`/etc/hosts`に

```
127.0.0.1 hostname.example.com
```

を追加するか、DNS 部分を書き換えるなどで調整を行って下さい。

### クライアント証明書を発行する

まず、sw-connector が接続するためのクライアント証明書を SCEP サーバから発行します。

#### SCEP サーバを構築する

SCEP サーバを構築して下さい。構築方法については scep レポジトリの[README](https://github.com/procube-open/scep/blob/main/README.md)を参照して下さい。

また、クライアントの登録とシークレット作成も併せて行って下さい。

#### scep クライアントファイルを実行する

まず、scep クライアントファイルをビルドして下さい。実行環境が MacOS の Apple M1 の場合だと scep レポジトリをクローンしたディレクトリ配下で以下のコマンドを実行することでビルドできます。

```
GOOS=darwin GOARCH=arm64 \
  go build -ldflags "\
  -X main.flServerURL=http://localhost:3000/scep \
  -X main.flPKeyFileName=key.pem \
  -X main.flCertFileName=cert.pem \
  -X main.flKeySize=2048 \
  -X main.flOrg=Procube \
  -X main.flCountry=JP \
  -X main.flDNSName=hostname.example.com \
  " -o scepclient-mac ./cmd/scepclient
```

その後、`./scepclient-mac -uid {クライアント} -secret {シークレット}`を実行することで`cert.pem`と`key.pem`を作成することができます。

### サーバ証明書を自己署名で作成する

サーバ証明書は SCEP サーバからの発行ではなく openssl を用いて作成します。
以下のコマンドを順に実行することで`server.crt`と`server.key`を作成することができます。

**秘密鍵の作成**

```
openssl genrsa -out server.key 2048
```

**CSR の作成**

```
openssl req -new -key server.key -out server.csr -config example/server_csr.conf
```

**サーバ証明書の作成**

```
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile example/server_csr.conf
```

ただし、`ca.crt`と`ca.key`は scep サーバで用いていたものをそのまま持ってきて下さい。

### sw-listener を起動する

sw-listener でサーバ証明書のパス指定を行うには環境変数を用います。
sw-listner を起動するには、以下のコマンドを順に実行して下さい。

```
cd sw_listener
```

```
cargo build
```

```
SWL_CERT_PATH={サーバ証明書の公開鍵のパス} \
SWL_KEY_PATH={サーバ証明書の秘密鍵のパス} \
SWL_CA_PATH={CA証明書の公開鍵のパス} \
target/debug/sw_listener
```

### sw-connector を起動する

sw-connector でクライアント証明書のパス指定を行うには`settings.json`というファイルを記述する必要があります。
以下のパラメータをそれぞれ指定して下さい。

- **client_cert_path**: クライアント証明書の公開鍵のパス
- **client_key_path**: クライアント証明書の秘密鍵のパス
- **ca_cert_path**: CA 証明書の公開鍵のパス
- **server_name**: "hostname.example.com",
- **service_port**: 11443

その後、sw-connector をビルドし、起動して下さい。

```
cd sw_connector
```

```
cargo build
```

```
target/build/sw_connector
```

### ポートを開設する

sw-listener にポート開設要求を API で送信します。
curl の場合は以下を実行することで送信できます。

```
curl --location 'http://localhost:8080/open' \
--header 'Content-Type: application/json' \
--data '{
    "uid": クライアント名(文字列),
    "port": 開設ポート(数字),
    "connect_address": 接続先アドレス(文字列),
    "connect_port": 接続先ポート(数字)
}'
```

以上で、開設要求を送信した内容で TCP 接続を受け付けるようになります。

## API

sw-listener が受け付ける API の一覧を以下に記述します。

### ポート開設(POST `/open`)

`/open`では、sw-lisnter に対して TCP 接続のポート開設を要求することができます。

#### リクエスト

リクエストに関して、`Content-Type`ヘッダは`application/json`として、リクエストボディは JSON で以下のパラメータを入力して下さい。

- **uid**(文字列): scep サーバで登録されているクライアントの uid
- **port**(数字): sw-listener が TCP 接続を受け付けるポート番号
- **connect_address**(文字列): sw-connector が接続するアドレス
- **connect_port**(数字): sw-connector が接続するポート番号

### ポート閉鎖(DELETE `/close`)

`/close`では、sw-listener が開設しているポートを閉じることができます。

#### リクエスト

リクエストに関して、`Content-Type`ヘッダは`application/json`として、リクエストボディは JSON で以下のパラメータを入力して下さい。

- **port**(数字): 閉鎖するポート番号
