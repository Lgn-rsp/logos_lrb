# LOGOS RID Builder
# Автор: LOGOS Core Dev

import random
import math
import time
import json
import os
from typing import Dict, Optional
from cryptography.fernet import Fernet

class RIDBuilder:
    def __init__(self):
        self.valid_symbols = ["☉", "??", "♁", "??", "??", "??", "Λ0", "∞"]
        self.default_freqs = [7.83, 1.618, 432.0, 864.0]
        self.generated: Dict[str, float] = {}  # RID -> timestamp
        self.rid_log_file = "rid_log.json"
        self.cipher = Fernet(Fernet.generate_key())  # Генерация ключа
        self.min_generate_interval = 60  # 1 минута
        self.lambda_zero = "Λ0"

    def generate_rid(self, symbol: Optional[str] = None, freq: Optional[float] = None) -> Optional[str]:
        """Генерирует новый RID с проверкой на спам и уникальность."""
        now = time.time()
        # Проверка частоты генерации
        for timestamp in self.generated.values():
            if now - timestamp < self.min_generate_interval:
                print(f"[!] Слишком частая генерация RID")
                self.log_event(f"Слишком частая генерация RID")
                return None

        # Выбор символа с приоритетом Λ0
        symbol = symbol or (self.lambda_zero if random.random() < 0.3 else random.choice(self.valid_symbols))
        if symbol not in self.valid_symbols:
            print(f"[!] Недопустимый символ: {symbol}")
            self.log_event(f"Недопустимый символ: {symbol}")
            return None

        freq = round(freq or random.choice(self.default_freqs), 3)
        if not (0.1 <= freq <= 10000.0):
            print(f"[!] Недопустимая частота: {freq}")
            self.log_event(f"Недопустимая частота: {freq}")
            return None

        phase = round(random.uniform(-math.pi, math.pi), 4)
        rid = f"{symbol}@{freq}Hzφ{phase}"

        # Проверка уникальности
        if rid in self.generated:
            print(f"[!] RID уже существует: {rid}")
            self.log_event(f"RID уже существует: {rid}")
            return None

        # Проверка через RCP (заглушка)
        if not self.validate_with_rcp(symbol, freq, phase):
            print(f"[!] RCP не подтвердил RID: {rid}")
            self.log_event(f"RCP не подтвердил RID: {rid}")
            return None

        self.generated[rid] = now
        self.log_rid(rid)
        return rid

    def parse_rid(self, rid: str) -> Dict:
        """Разбирает RID на компоненты."""
        try:
            parts = rid.split("@")
            symbol = parts[0]
            freq_phase = parts[1].replace("Hz", "").split("φ")
            frequency = float(freq_phase[0])
            phase = float(freq_phase[1])
            return {
                "symbol": symbol,
                "frequency": frequency,
                "phase": phase
            }
        except Exception as e:
            print(f"[!] Ошибка разбора RID: {e}")
            self.log_event(f"Ошибка разбора RID: {e}")
            return {}

    def validate_rid(self, rid: str) -> bool:
        """Проверяет валидность RID."""
        parsed = self.parse_rid(rid)
        if not parsed:
            return False
        valid = (
            parsed["symbol"] in self.valid_symbols and
            0.1 <= parsed["frequency"] <= 10000.0 and
            -math.pi <= parsed["phase"] <= math.pi
        )
        if not valid:
            self.log_event(f"Невалидный RID: {rid}")
        return valid

    def validate_with_rcp(self, symbol: str, frequency: float, phase: float) -> bool:
        """Заглушка для проверки через rcp_engine.rs."""
        # TODO: Интеграция с rcp_engine.rs
        return symbol == self.lambda_zero or abs(frequency - 7.83) < 0.1

    def log_rid(self, rid: str):
        """Логирует создание RID."""
        entry = {
            "event": "rid_generate",
            "rid": rid,
            "timestamp": time.time()
        }
        self._write_log(entry)

    def log_event(self, message: str):
        """Логирует событие."""
        entry = {
            "event": "rid_builder",
            "message": message,
            "timestamp": time.time()
        }
        self._write_log(entry)

    def _write_log(self, entry: Dict):
        """Сохраняет лог с шифрованием."""
        log_data = json.dumps(entry) + "\n"
        encrypted_data = self.cipher.encrypt(log_data.encode())
        with open(self.rid_log_file, "ab") as f:
            f.write(encrypted_data + b"\n")

if __name__ == "__main__":
    builder = RIDBuilder()
    new_rid = builder.generate_rid()
    if new_rid:
        print("Сгенерированный RID:", new_rid)
        parsed = builder.parse_rid(new_rid)
        print("Разбор:", parsed)
        print("RID валиден?", builder.validate_rid(new_rid))
