set -euo pipefail

SOCKET=UNIX-CONNECT:socket

function usage() {
  echo "Usage:"
  echo "$0 init           -- initialize secrets store"
  echo "$0 signin         -- cache passpharse"
  echo "$0 encrypt NAME   -- encrypt stdin to store path NAME"
  echo "$0 decrypt NAME   -- decrypt store path NAME to stdout"
}

function get_passphrase() {
  local PASSPHRASE
  read -s -p "Enter passphrase: " PASSPHRASE
  echo -n "set-passphrase "$PASSPHRASE"" | socat - $SOCKET
  PASSPHRASE=''
  echo
}

function encrypt() {
  NAME="$1"
  cat <(echo "encrypt $NAME") - | socat - $SOCKET
}

function decrypt() {
  NAME="$1"
  echo -n "decrypt $NAME" | socat - $SOCKET
}

function init() {
  get_passphrase
  echo 'Okay' | encrypt .__init
}

function signin() {
  get_passphrase
  decrypted=$(decrypt .__init)
  if [[ "$decrypted" != "Okay" ]]; then
    echo "Wrong passphrase" >&2
    exit 1
  fi
}

if [ "$#" -gt 2 ]; then
    usage
    exit 1
fi

verb="$1"

# Validate and call the corresponding function
case "$verb" in
    init|signin)
        if [ "$#" -ne 1 ]; then
          usage
          exit 1
        fi
        "$verb"
        ;;
    encrypt|decrypt)
        if [ "$#" -ne 2 ]; then
          usage
          exit 1
        fi
        "$verb" "$2"
        ;;
    *)
        echo "Invalid argument: $verb."
        usage
        exit 1
        ;;
esac
