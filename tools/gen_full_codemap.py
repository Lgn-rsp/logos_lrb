#!/usr/bin/env python3
# gen_full_codemap.py — cоздаёт единый текстовый слепок исходников из заданных директорий.
# Использование:
#   python3 gen_full_codemap.py OUTPUT.txt DIR1 [DIR2 ...]
#
# Пример:
#   python3 gen_full_codemap.py /root/logos_snapshot/SNAPSHOT_$(date +%F_%H%M).txt /root/logos_lrb /root/logos_rsp

import os, sys, hashlib, time

OK_EXT = {
    '.rs','.py','.tsx','.ts','.js','.jsx','.go',
    '.html','.htm','.css','.scss','.md','.txt',
    '.yaml','.yml','.toml','.ini','.cfg','.conf',
    '.sh','.bash','.zsh','.sql','.proto','.graphql',
    '.env.example','.service','.timer'
}

EXCLUDE_DIR_PREFIXES = (
    '.git','target','node_modules','build','dist','out','venv','.venv','__pycache__',
    '.idea','.vscode','.fleet','.DS_Store','coverage','.pytest_cache',
    '.cargo','.gradle','android/app/build','ios/Pods','.dart_tool',
    'tools/.venv','tools/venv','.husky'
)

EXCLUDE_FILE_PATTERNS = (
    '.env',        # любые .env (чтобы не потянуть реальные секреты)
    '.pem','.key','.crt','.p12','.keystore','.jks',
    '.sqlite','.db','.db3','.sqlite3',
    '.lock','.bin','.wasm','.o','.a'
)

MAX_FILE_BYTES = 400_000       # не включать слишком большие файлы
MAX_TOTAL_BYTES = 300_000_000  # общий предел (300 МБ, чтобы не улететь в космос)

def is_excluded_dir(path):
    norm = path.replace('\\','/')
    parts = norm.split('/')
    for p in parts:
        for ex in EXCLUDE_DIR_PREFIXES:
            if p == ex or norm.startswith(ex + '/'):
                return True
    return False

def is_ok_file(path):
    # исключить секреты/бинарники по шаблонам имени
    low = path.lower()
    for pat in EXCLUDE_FILE_PATTERNS:
        if low.endswith(pat) or f"/{pat}" in low:
            return False
    # по расширениям
    _, ext = os.path.splitext(path)
    if ext.lower() in OK_EXT:
        try:
            if os.path.getsize(path) <= MAX_FILE_BYTES:
                return True
        except FileNotFoundError:
            return False
    return False

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path,'rb') as r:
        while True:
            b = r.read(1024*1024)
            if not b: break
            h.update(b)
    return h.hexdigest()

def collect_files(roots):
    out = []
    for root in roots:
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            # пропуск скрытых/исключённых директорий
            norm_dp = dp.replace('\\','/')
            if is_excluded_dir(norm_dp):
                dn[:] = []  # не спускаться ниже
                continue
            for f in fn:
                p = os.path.join(dp,f)
                norm = p.replace('\\','/')
                # пропускаем скрытые файлы
                if any(seg.startswith('.') and seg not in ('.env.example',) for seg in norm.split('/')):
                    # .env.example оставляем
                    pass
                if is_ok_file(norm):
                    out.append(norm)
    out = sorted(set(out))
    return out

def main():
    if len(sys.argv) < 3:
        print("Usage: gen_full_codemap.py OUTPUT.txt DIR1 [DIR2 ...]", file=sys.stderr)
        sys.exit(1)
    output = os.path.abspath(sys.argv[1])
    roots  = sys.argv[2:]
    files  = collect_files(roots)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')

    total_written = 0
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w', encoding='utf-8', errors='replace') as w:
        w.write("# FULL CODE SNAPSHOT\n")
        w.write(f"Generated: {ts}\n")
        w.write(f"Roots: {', '.join(os.path.abspath(r) for r in roots)}\n")
        w.write(f"Files count: {len(files)}\n")
        w.write("\n## Table of Contents\n")
        for i, p in enumerate(files, 1):
            anchor = f"{i}-{p.replace('/','-')}"
            w.write(f"{i}. {p}  ->  #{anchor}\n")
        w.write("\n---\n")

        for i, p in enumerate(files, 1):
            try:
                size = os.path.getsize(p)
                sha  = sha256_of_file(p)
                with open(p,'r',encoding='utf-8',errors='replace') as r:
                    data = r.read()
            except Exception as e:
                data = f"<<error reading {p}: {e}>>"
                size = -1
                sha  = "n/a"

            header = f"\n## {i}. {p}\n#size={size} bytes  sha256={sha}\n<a name=\"{i}-{p.replace('/','-')}\"></a>\n\n"
            body   = "```text\n" + data + "\n```\n"
            chunk  = header + body
            enc    = chunk.encode('utf-8', errors='replace')
            if total_written + len(enc) > MAX_TOTAL_BYTES:
                w.write("\n\n<< STOPPED: reached MAX_TOTAL_BYTES limit >>\n")
                break
            w.write(chunk)
            total_written += len(enc)

    print(f"[ok] Wrote snapshot to: {output}")
    print(f"[info] Files included: {len(files)}")
    print(f"[info] Approx bytes written: {total_written}")

if __name__ == '__main__':
    main()
