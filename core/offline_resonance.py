# LOGOS Offline Resonance Module
# Автор: LOGOS Core Dev

import json
import os
import time
from datetime import datetime
from typing import Dict
from cryptography.fernet import Fernet
import re

class OfflineResonance:
    def __init__(self, storage_file: str = "offline_phase_state.json", encryption_key: str = None):
        self.storage_file = storage_file
        self.cipher = Fernet(encryption_key or Fernet.generate_key()) if encryption_key else None
        self.state = {
            "last_sync": 0,
            "symbol": "Λ0",
            "frequency": 7.83,
            "phase": 0.0,
            "pending_tx": []  # Очередь оффлайн-транзакций
        }
        self.valid_symbols = {"☉", "??", "♁", "??", "??", "??", "Λ0", "∞"}
        self.log_file = "offline_resonance_log.json"
        self.load_state()

    def validate_symbol(self, symbol: str) -> bool:
        """Проверяет, состоит ли символ из допустимых значений."""
        return bool(re.match(r'^[☉??♁??????Λ0∞]+$', symbol))

    def validate_frequency(self, frequency: float) -> bool:
        """Проверяет частоту на допустимый диапазон."""
        return 0.1 <= frequency <= 10000.0

    def load_state(self):
        """Загружает состояние из файла с расшифровкой."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "rb") as f:
                    data = f.read()
                    if self.cipher:
                        data = self.cipher.decrypt(data)
                    self.state = json.loads(data)
            except Exception as e:
                print(f"[!] Ошибка чтения локального состояния: {e}. Используется по умолчанию.")
        else:
            self.save_state()

    def save_state(self):
        """Сохраняет состояние в файл с шифрованием."""
        data = json.dumps(self.state, indent=2).encode()
        if self.cipher:
            data = self.cipher.encrypt(data)
        with open(self.storage_file, "wb") as f:
            f.write(data)

    def update_phase(self, symbol: str, frequency: float, phase: float) -> bool:
        """Обновляет фазовое состояние с валидацией."""
        if not self.validate_symbol(symbol):
            print(f"[!] Недопустимый символ: {symbol}")
            return False
        if not self.validate_frequency(frequency):
            print(f"[!] Недопустимая частота: {frequency}")
            return False
        if not (-math.pi <= phase <= math.pi):
            print(f"[!] Недопустимая фаза: {phase}")
            return False

        self.state["symbol"] = symbol
        self.state["frequency"] = frequency
        self.state["phase"] = phase
        self.state["last_sync"] = int(time.time())
        self.save_state()
        self.log_update(symbol, frequency, phase)
        print(f"[OFFLINE] Фаза обновлена: {symbol}, {frequency} Hz, φ = {phase}")
        return True

    def add_offline_tx(self, tx: Dict):
        """Добавляет оффлайн-транзакцию в очередь."""
        if self.validate_symbol(tx.get("symbol", "")) and "amount" in tx:
            self.state["pending_tx"].append(tx)
            self.save_state()
            self.log_tx(tx)
            print(f"[OFFLINE] Транзакция добавлена: {tx}")
        else:
            print("[!] Недопустимая транзакция")

    def get_current_phase(self) -> Dict:
        """Возвращает текущее состояние."""
        return self.state

    def is_stale(self, max_age: int = 600) -> bool:
        """Проверяет, устарело ли локальное состояние."""
        now = int(time.time())
        return (now - self.state["last_sync"]) > max_age

    def log_update(self, symbol: str, frequency: float, phase: float):
        """Логирует обновление фазы."""
        log_entry = {
            "event": "phase_update",
            "symbol": symbol,
            "frequency": frequency,
            "phase": phase,
            "timestamp": datetime.utcnow().timestamp()
        }
        self._write_log(log_entry)

    def log_tx(self, tx: Dict):
        """Логирует оффлайн-транзакцию."""
        log_entry = {
            "event": "offline_tx",
            "tx": tx,
            "timestamp": datetime.utcnow().timestamp()
        }
        self._write_log(log_entry)

    def _write_log(self, entry: Dict):
        """Записывает лог в файл для resonance_analyzer.py."""
        with open(self.log_file, "a") as f:
            json.dump(entry, f)
            f.write("\n")

if __name__ == "__main__":
    offline = OfflineResonance()
    # Тест обновления фазы
    offline.update_phase("☉??♁", 1.618, 0.785)
    print("Текущее состояние:", offline.get_current_phase())
    print("Устарело?", offline.is_stale())
    # Тест оффлайн-транзакции
    tx = {"symbol": "??", "amount": 3.14, "to": "RID_♁☿"}
    offline.add_offline_tx(tx)
