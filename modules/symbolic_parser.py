# LOGOS Symbolic Parser
# Автор: LOGOS Core Dev

import re
import math
from typing import List, Dict, Optional
from cryptography.fernet import Fernet
import json
import time

class SymbolicParser:
    def __init__(self):
        self.valid_symbols = ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]
        self.lambda_zero = "Λ0"
        self.pattern = re.compile(r"(?P<symbol>[☉??♁??????Λ0∞])@(?P<freq>[0-9\.]+)Hzφ(?P<phase>[-0-9\.]+)")
        self.log_file = "symbolic_parser_log.json"
        self.cipher = Fernet(Fernet.generate_key())
        self.rid_cache: Dict[str, Dict] = {}  # Кэш для RID

    def extract_rids(self, text: str) -> List[str]:
        """Находит все валидные RID в тексте."""
        matches = self.pattern.findall(text)
        rids = [f"{m[0]}@{m[1]}Hzφ{m[2]}" for m in matches if m[0] in self.valid_symbols]
        self.log_event(f"[EXTRACT] Найдено {len(rids)} RID: {rids}")
        return rids

    def parse_rid(self, rid: str) -> Optional[Dict]:
        """Парсит одиночный RID в структуру."""
        # Проверка кэша
        if rid in self.rid_cache:
            self.log_event(f"[CACHE] RID {rid} из кэша")
            return self.rid_cache[rid]

        try:
            match = self.pattern.match(rid)
            if not match:
                self.log_event(f"[!] Неверный формат RID: {rid}")
                return None

            symbol = match.group("symbol")
            if symbol not in self.valid_symbols:
                self.log_event(f"[!] Недопустимый символ: {symbol}")
                return None

            freq = float(match.group("freq"))
            phase = float(match.group("phase"))

            # Проверка диапазонов
            if not (0.1 <= freq <= 10000.0):
                self.log_event(f"[!] Недопустимая частота: {freq}")
                return None
            if not (-math.pi <= phase <= math.pi):
                self.log_event(f"[!] Недопустимая фаза: {phase}")
                return None

            # Проверка через RCP (заглушка)
            if not self.validate_with_rcp(symbol, freq, phase):
                self.log_event(f"[!] RCP не подтвердил RID: {rid}")
                return None

            result = {
                "symbol": symbol,
                "frequency": freq,
                "phase": phase,
                "is_lambda_zero": symbol == self.lambda_zero
            }
            self.rid_cache[rid] = result
            self.log_event(f"[PARSE] Успешно разобран RID: {rid}")
            return result
        except Exception as e:
            self.log_event(f"[!] Ошибка разбора RID: {e}")
            return None

    def extract_symbols(self, text: str) -> List[str]:
        """Извлекает все допустимые символы в тексте."""
        symbols = [s for s in text if s in self.valid_symbols]
        if self.lambda_zero in symbols:
            symbols.insert(0, symbols.pop(symbols.index(self.lambda_zero)))  # Приоритет Λ0
        self.log_event(f"[EXTRACT] Найдено {len(symbols)} символов: {symbols}")
        return symbols

    def validate_rid_format(self, rid: str) -> bool:
        """Проверяет соответствие RID формату."""
        result = bool(self.parse_rid(rid))
        self.log_event(f"[VALIDATE] RID {rid} {'валиден' if result else 'невалиден'}")
        return result

    def validate_with_rcp(self, symbol: str, freq: float, phase: float) -> bool:
        """Заглушка для проверки через rcp_engine.rs."""
        return symbol == self.lambda_zero or (abs(freq - 7.83) < 0.1 and abs(phase) < 0.05)

    def log_event(self, message: str):
        """Логирует событие с шифрованием."""
        entry = {
            "event": "symbolic_parser",
            "message": message,
            "timestamp": time.time()
        }
        encrypted = self.cipher.encrypt(json.dumps(entry).encode() + b"\n")
        with open(self.log_file, "ab") as f:
            f.write(encrypted)

if __name__ == "__main__":
    parser = SymbolicParser()
    test = "Пример: ☉@432.0Hzφ0.618, Λ0@7.83Hzφ0.0 и ♁@1.618Hzφ-0.314"
    rids = parser.extract_rids(test)
    print("Найденные RID:", rids)
    for r in rids:
        parsed = parser.parse_rid(r)
        print("Разбор:", parsed)
