#!/usr/bin/env bash
# jpki-ssh-agent インストーラ (Debian/Ubuntu 系)。
# venv + 依存の導入、PaSoRi 用 udev ルール設置を行う。
# 侵襲的な port100 blacklist は同意プロンプトで確認してから実行する。
set -euo pipefail

VENV="${JPKI_VENV:-$HOME/.venvs/jpki-ssh-agent}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ask() { local p="$1" d="${2:-N}" a; read -rp "$p " a || true; a="${a:-$d}"; [[ "$a" =~ ^[Yy] ]]; }

echo "=== jpki-ssh-agent installer ==="
echo "venv: $VENV"
echo

if ! command -v apt-get >/dev/null 2>&1; then
  echo "!! apt-get が見つかりません。Debian/Ubuntu 系以外は README の『手動セットアップ』を参照してください。"
  exit 1
fi
command -v python3 >/dev/null || { echo "!! python3 が必要です"; exit 1; }

# --- venv + Python 依存 ---
echo "[1/4] venv と Python 依存 (cryptography, nfcpy) を用意..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q cryptography nfcpy
echo "    OK"

# --- 任意: PC/SC (CCID リーダー) ---
echo
echo "[2/4] CCID リーダー (Sony RC-S300 / ACR1252U 等) を使いますか？"
echo "      ※PaSoRi RC-S380 だけの人は 'N' でOK（nfcpy で動きます）。"
if ask "      pyscard と pcscd を入れる? [y/N]:" N; then
  echo "    apt で swig / libpcsclite-dev / pcscd を導入 (sudo)..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq swig libpcsclite-dev pcscd
  "$VENV/bin/pip" install -q pyscard
  sudo systemctl enable --now pcscd || true
  echo "    OK (PC/SC 有効)"
else
  echo "    skip (nfcpy のみ)"
fi

# --- PaSoRi 用 udev ルール + plugdev ---
echo
echo "[3/4] PaSoRi(nfcpy) を非 root で使うための udev ルールを設置 (sudo)..."
sudo tee /etc/udev/rules.d/99-jpki-pasori.rules >/dev/null <<'EOF'
# Sony PaSoRi (RC-S330/02e1, RC-S370/06c1, RC-S380/06c3) を plugdev で開ける
SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="02e1", GROUP="plugdev", MODE="0664"
SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c1", GROUP="plugdev", MODE="0664"
SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c3", GROUP="plugdev", MODE="0664"
EOF
sudo udevadm control --reload
if ! id -nG "$USER" | grep -qw plugdev; then
  sudo usermod -aG plugdev "$USER"
  echo "    plugdev グループに追加しました（反映には再ログインが必要）。"
fi
echo "    OK"

# --- 任意かつ侵襲的: port100 blacklist ---
echo
echo "[4/4] nfcpy は PaSoRi をカーネルの 'port100' ドライバと取り合うことがあります。"
echo "      blacklist すると nfcpy が安定しますが、neard 等カーネル NFC スタックを使う"
echo "      他の用途は動かなくなります（侵襲的操作）。"
if ask "      port100 を無効化(blacklist)しますか? [y/N]:" N; then
  sudo modprobe -r port100 2>/dev/null || true
  echo 'blacklist port100' | sudo tee /etc/modprobe.d/blacklist-nfc.conf >/dev/null
  echo "    port100 を blacklist しました。"
else
  echo "    skip（nfcpy が 'already used' 等で失敗する場合のみ、後で手動で実施してください）。"
fi

cat <<EOF

=== 完了 ===
使い方:
  1) 公開鍵を出してサーバに登録(初回のみ):
       $VENV/bin/python $HERE/jpki_agent.py --print-key
       # 出力の ssh-rsa 行を相手の ~/.ssh/authorized_keys へ
  2) 日常は端末1枚で完結:
       $VENV/bin/python $HERE/jpki_agent.py ssh user@server
       # 「カードを載せて PIN」→ そのままログイン

詳細と注意（PIN ロック・証明書更新・立ち位置・常駐モード）は README.md を参照。
EOF
