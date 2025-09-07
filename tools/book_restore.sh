#!/usr/bin/env bash
set -euo pipefail

BOOK="${1:-}"
if [[ -z "$BOOK" || ! -f "$BOOK" ]]; then
  echo "usage: $0 /path/to/LOGOS_LRB_BOOK_*.txt"; exit 1
fi

echo "[*] Restoring files from: $BOOK"
RESTORED=0
BADHASH=0

# прочитаем книгу и вытащим секции
# формат: BEGIN FILE <path>\n# sha256: <hex>\n<<'EOF'\n...EOF\nEND FILE
awk '
  /^===== BEGIN FILE / {
    inblock=1
    path=""
    sha=""
    gsub(/^===== BEGIN FILE /,"")
    gsub(/ =====$/,"")
    path=$0
    next
  }
  inblock && /^# sha256:/ {
    sha=$2
    next
  }
  inblock && /^<<'\''EOF'\''/ { collecting=1; content=""; next }
  collecting && /^EOF$/ { collecting=0; inblock=2; next }
  inblock==1 && !collecting { next }
  collecting { content = content $0 "\n"; next }
  inblock==2 && /^===== END FILE / {
    # записываем файл
    # создадим директорию
    cmd = "mkdir -p \"" path "\""
    sub(/\/[^\/]+$/, "", cmdpath=path) # dir part
    if (cmdpath != "") {
      system("mkdir -p \"" cmdpath "\"")
    }
    # записываем
    f = path
    gsub(/\r$/,"",content)
    # защитимся от /etc/... если нет прав — предложим sudo
    # но здесь просто пишем как есть
    outfile = path
    # если путь абсолютный, пишем в тот же абсолютный; если относительный — относительно cwd
    # создадим временный и заменим
    tmpfile = outfile ".tmp.restore"
    # в shell передам через printf
    print content > tmpfile
    close(tmpfile)
    # проверка sha256 если есть
    if (sha != "" && sha != "N/A") {
      cmdsum = "sha256sum \"" tmpfile "\" | awk '\''{print $1}'\''"
      cmdsum | getline got
      close(cmdsum)
      if (got != sha) {
        print "[WARN] sha256 mismatch for " outfile " expected=" sha " got=" got
        BADHASH++
      }
    }
    system("install -m 0644 \"" tmpfile "\" \"" outfile "\"")
    system("rm -f \"" tmpfile "\"")
    print "[OK] restored " outfile
    RESTORED++
    inblock=0
    next
  }
  END {
    # summary в AWK не выведем; сделаем в оболочке
  }
' "$BOOK"

echo "[*] Restored files: $RESTORED"
if [[ "${BADHASH:-0}" -gt 0 ]]; then
  echo "[!] WARNING: sha256 mismatches: $BADHASH"
fi

echo "[*] Done. Проверь права на системные файлы, возможно потребуется sudo chown/chmod."
