# LOGOS rLGN ⇆ LGN Converter
# Автор: LOGOS Core Dev

import json
import time
import math
from typing import Dict
from cryptography.fernet import Fernet
import os

class rLGNConverter:
    def __init__(self, storage_file: str = "lgn_wallet.json", encryption_key: str = None):
        self.storage_file = storage_file
        self.cipher = Fernet(encryption_key or Fernet.generate_key()) if encryption_key else None
        self.state = {
            "LGN": 0.0,
            "rLGN": 0.0,
            "last_conversion": 0,
            "conversion_log": []
        }
        self.lambda_zero = "Λ0"
        self.min_conversion_interval = 60  # 1 минута
        self.log_file = "conversion_log.json"
        self.load_state()

    def load_state(self):
        """Загружает состояние с расшифровкой."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "rb") as f:
                    data = f.read()
                    if self.cipher:
                        data = self.cipher.decrypt(data)
                    self.state = json.loads(data)
            except Exception as e:
                print(f"[!] Ошибка чтения состояния: {e}. Используется по умолчанию.")
        else:
            self.save_state()

    def save_state(self):
        """Сохраняет состояние с шифрованием."""
        data = json.dumps(self.state, indent=2).encode()
        if self.cipher:
            data = self.cipher.encrypt(data)
        with open(self.storage_file, "wb") as f:
            f.write(data)

    def validate_phase(self, phase: float) -> bool:
        """Проверяет фазу на допустимый диапазон."""
        return -math.pi <= phase <= math.pi

    def convert_to_lgn(self, amount: float, phase: float, symbol: str = "") -> bool:
        """Конвертирует rLGN в LGN с учетом фазы и Λ0."""
        if not self._can_convert(amount, phase, "rLGN"):
            return False

        multiplier = self._phase_multiplier(phase, symbol)
        converted = amount * multiplier
        self.state["rLGN"] -= amount
        self.state["LGN"] += converted
        self._log("rLGN→LGN", amount, converted, phase, symbol)
        self.state["last_conversion"] = time.time()
        self.save_state()
        return True

    def convert_to_rlgn(self, amount: float, phase: float, symbol: str = "") -> bool:
        """Конвертирует LGN в rLGN с учетом фазы и Λ0."""
        if not self._can_convert(amount, phase, "LGN"):
            return False

        penalty = self._phase_penalty(phase, symbol)
        converted = amount * penalty
        self.state["LGN"] -= amount
        self.state["rLGN"] += converted
        self._log("LGN→rLGN", amount, converted, phase, symbol)
        self.state["last_conversion"] = time.time()
        self.save_state()
        return True

    def _can_convert(self, amount: float, phase: float, source: str) -> bool:
        """Проверяет возможность конвертации."""
        if amount <= 0 or amount > self.state[source]:
            print(f"[!] Недостаточно {source}: {amount}")
            return False
        if not self.validate_phase(phase):
            print(f"[!] Недопустимая фаза: {phase}")
            return False
        if time.time() - self.state["last_conversion"] < self.min_conversion_interval:
            print("[!] Слишком частая конвертация")
            return False
        return True

    def _phase_multiplier(self, phase: float, symbol: str) -> float:
        """Вычисляет мультипликатор с бонусом для Λ0."""
        base = max(0.1, min(1.5, 1.0 + math.cos(phase)))
        if symbol == self.lambda_zero:
            base *= 1.2  # Бонус за Λ0
        return base

    def _phase_penalty(self, phase: float, symbol: str) -> float:
        """Вычисляет штраф с учетом Λ0."""
        base = max(0.5, min(1.0, 1.0 - abs(math.sin(phase))))
        if symbol == self.lambda_zero:
            base = min(1.0, base * 1.1)  # Смягчение штрафа для Λ0
        return base

    def _log(self, direction: str, original: float, result: float, phase: float, symbol: str):
        """Логирует конвертацию в файл и консоль."""
        entry = {
            "direction": direction,
            "original": round(original, 5),
            "result": round(result, 5),
            "phase": round(phase, 4),
            "symbol": symbol,
            "timestamp": time.time()
        }
        self.state["conversion_log"].append(entry)
        with open(self.log_file, "a") as f:
            json.dump(entry, f)
            f.write("\n")
        print(f"[{direction}] {original} → {result} @ φ={phase:.3f}, Symbol={symbol}")

    def get_balances(self) -> Dict:
        """Возвращает текущие балансы."""
        return {
            "LGN": round(self.state["LGN"], 5),
            "rLGN": round(self.state["rLGN"], 5)
        }

if __name__ == "__main__":
    converter = rLGNConverter()
    converter.state["rLGN"] = 10.0
    converter.state["LGN"] = 5.0
    converter.convert_to_lgn(2.5, 0.785, "Λ0")
    converter.convert_to_rlgn(1.0, 1.047, "☉")
    print("Баланс:", converter.get_balances())
