# jpki-ssh-agent

**マイナンバーカードを SSH の認証鍵にする ssh-agent。**
家に転がっている e-Tax 用の PaSoRi（Sony RC-S380 など）でそのまま動きます。CCID リーダーも OpenSC も PKCS#11 も不要。

> An ssh-agent that lets you log in over SSH using your Japanese My Number Card
> (マイナンバーカード). Works with the PaSoRi RC-S380 via `nfcpy`, or any CCID
> reader via PC/SC. The private key never leaves the card.

カードに入っている**利用者証明用電子証明書**の鍵ペアを使い、SSH の公開鍵認証の challenge をカード内で署名します。**秘密鍵はカードから一切出ません**。カードをかざして 4 桁 PIN を入れた瞬間だけ署名が行われます。

---

## ⚠️ はじめに（必ず読む）

- **これはローカルの公開鍵認証ツールです。** カードの公開鍵を自分のサーバの `authorized_keys` に登録し、署名をカードで行うだけ。JPKI の**失効確認もオンライン本人確認もしません**。公的個人認証サービスの認定事業者サービスとは無関係で、**マイナンバー（12 桁の個人番号）は一切使いません**（使うのは利用者証明用証明書の鍵だけ）。
- **PIN を 3 回連続で間違えるとカードがロックされます。** 解除は市区町村の窓口（またはコンビニの対応サービス）が必要です。本ツールは「残り試行回数を事前に読む／1 回だけ照合／失敗したら即停止（自動リトライしない）」で事故を防いでいますが、**PIN の管理は自己責任**です。
- **自己責任でどうぞ。** MIT ライセンス、無保証。作者は片手間メンテです（Issue は見られないことがあります）。

---

## 仕組み

```
マイナンバーカード (利用者証明用鍵, RSA2048)
   │  SELECT AP → VERIFY PIN → SELECT 鍵EF → COMPUTE SIG (80 2A 00 80 + SHA-256 DigestInfo)
   ▼
カードリーダー ──（PC/SC: pyscard  /  PaSoRi: nfcpy）──▶ jpki_agent.py
   │  ssh-agent プロトコル (SSH_AGENTC_SIGN_REQUEST → 256B 署名)
   ▼
OpenSSH クライアント ──▶ 公開鍵認証でログイン
```

カードが返す署名は `00 01 FF..FF 00 ‖ SHA-256 DigestInfo ‖ hash` = **RSASSA-PKCS1-v1.5 / SHA-256**、すなわち SSH の `rsa-sha2-256`（512 も対応）と完全に一致します。サーバ側は `PubkeyAuthentication yes` と `rsa-sha2-256/512` を受理すること（OpenSSH 既定 ON）だけが要件で、CA も PKCS#11 も不要です。

## 対応リーダー

| バックエンド | 対応リーダー | 備考 |
|---|---|---|
| **nfcpy** | Sony PaSoRi RC-S330 / RC-S360 / RC-S370 / RC-S380 など | CCID 非準拠で PC/SC が使えない PaSoRi はこちら |
| **PC/SC** (pyscard) | Sony RC-S300、ACR1252U など CCID リーダー全般 | `pcscd` が認識する機種 |

両方入っていれば **PC/SC を優先 → 無ければ nfcpy** に自動フォールバック。環境変数 `JPKI_BACKEND=pcsc|nfc` で強制もできます。

## インストール

```bash
git clone https://github.com/yasunorioi/jpki-ssh-agent.git
cd jpki-ssh-agent
./install.sh
```

`install.sh` は venv の作成と依存（`cryptography`, `nfcpy`、任意で `pyscard`）の導入、PaSoRi 用の udev ルール設置を行います。
PaSoRi で使う場合に必要な `port100` カーネルドライバの無効化（blacklist）は、**他の NFC 用途を壊しうるため同意プロンプトで確認**してから実行します（手動でやりたい人は下記「手動セットアップ」参照）。

## 使い方

PY=~/.venvs/jpki-ssh-agent/bin/python として読み替えてください。

### 初回だけ：公開鍵をサーバに登録

```bash
# カードから公開鍵を抽出（初回はカードをかざす。カードによっては PIN も一度）
$PY jpki_agent.py --print-key
#   → ~/.config/jpki-agent/pubkey.pub にもキャッシュされる

# その ssh-rsa 行をサーバの authorized_keys に登録（手貼り）
cat ~/.config/jpki-agent/pubkey.pub | ssh user@server 'cat >> ~/.ssh/authorized_keys'
```

### 日常：端末 1 枚で完結（推奨）

```bash
$PY jpki_agent.py ssh user@server
#   → 「カードを載せて PIN」を一度聞かれる
#   → そのまま ssh が起動し、裏の使い捨て agent が署名してログイン
#   → 追加の端末も GUI も不要。ssh の引数はそのまま後ろに渡せる:
$PY jpki_agent.py ssh -p 2222 user@server -- uptime
```

`ssh` サブコマンドは、PIN を**先に**この端末で受け取り（まだ ssh が端末を奪う前）、非対話モードの agent を一時的に裏で立てて `ssh` を exec します。PIN は agent プロセスのメモリに一時保持されるだけで、argv・ファイル・ネットワークには出ません。ssh 終了で agent も破棄されます。クライアントがヘッドレスでも動きます。

### 別法：agent を常駐させる（複数接続をまとめたいとき・2 端末）

```bash
# 端末A: agent を前面で起動（署名のたびここで PIN を聞かれる）
$PY jpki_agent.py
#   → 表示される export SSH_AUTH_SOCK=... をコピー

# 端末B:
export SSH_AUTH_SOCK=/run/user/1000/jpki-agent.XXXX.sock
ssh -o IdentitiesOnly=yes -i ~/.config/jpki-agent/pubkey.pub user@server
```

> **Tip:** デスクトップ環境では `SSH_AUTH_SOCK` が GNOME Keyring 等（例: `/run/user/1000/gcr/ssh`）に既定設定されていることがあります。常駐モードでは必ず jpki-agent が表示したソケットパスで上書きしてください（`ssh` サブコマンドなら自動で設定されるので不要）。`ssh-add -l` でこの agent の鍵 1 本が見えれば接続 OK です。

## 運用上の注意

- **1 回の SSH ＝ カード 1 タップ＋ PIN 1 回。** これは安全側の既定です（都度 PIN）。カードは先にリーダーへ載せてから ssh してください（未検出は 30 秒待って失敗します）。
- **利用者証明用電子証明書は約 5 年で更新**され、引越し等でも失効します。その際は鍵ペアが変わるので、`--print-key` を取り直して `authorized_keys` を貼り替えてください。
- 複数リーダーがある等で選択を固定したい場合は `JPKI_BACKEND=pcsc` / `JPKI_BACKEND=nfc`。

## 手動セットアップ（install.sh を使わない場合）

```bash
python3 -m venv ~/.venvs/jpki-ssh-agent
~/.venvs/jpki-ssh-agent/bin/pip install cryptography nfcpy
# CCID リーダーを使うなら（Debian/Ubuntu 例）:
#   sudo apt install swig libpcsclite-dev pcscd
#   ~/.venvs/jpki-ssh-agent/bin/pip install pyscard

# PaSoRi(nfcpy) を非 root で使うための udev ルール:
sudo tee /etc/udev/rules.d/99-jpki-pasori.rules >/dev/null <<'EOF'
SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="02e1", GROUP="plugdev", MODE="0664"
SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c1", GROUP="plugdev", MODE="0664"
SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c3", GROUP="plugdev", MODE="0664"
EOF
sudo udevadm control --reload
sudo usermod -aG plugdev "$USER"   # 反映には再ログイン

# nfcpy が port100 カーネルドライバと取り合う場合のみ（他の NFC 用途を壊すので注意）:
#   sudo modprobe -r port100
#   echo 'blacklist port100' | sudo tee /etc/modprobe.d/blacklist-nfc.conf
```

## セキュリティ

- 秘密鍵はカードの IC 内にあり、本ツールは**署名要求をカードに投げて署名結果（256B）を受け取るだけ**。鍵の取り出しはしません（原理的にできません）。
- PIN は agent プロセス内で `getpass`（画面非表示）で受け取り、ログ・ファイル・ネットワークに一切残しません。照合は 1 回だけ、失敗したら即 `SSH_AGENT_FAILURE` を返して自動リトライしません。
- 脆弱性の報告は Issue ではなくメール等で（README 上部参照）。とはいえ片手間運用です。

## 謝辞・先行事例

JPKI の APDU 仕様は多くの有志の解析（`jpki/myna`, `libjeid`, OpenSC の JPKI fork, OSSTech の jpki-ssh/jpki-pam など）の上に成り立っています。本ツールの新しさは「**PC/SC を介さず nfcpy で PaSoRi を直接叩き、ssh-agent プロトコルを素実装することで、CCID リーダーを買わずに（＝家にある RC-S380 で）マイナ SSH を成立させた**」点にあります。

## ライセンス

MIT（`LICENSE` 参照）。無保証。
