# LOGOS Ritual Quest Engine
# Автор: LOGOS Core Dev

import json
import time
import os
from typing import Dict
from cryptography.fernet import Fernet
from resonance_analyzer import ResonanceAnalyzer  # Для оценки резонанса

class RitualQuest:
    def __init__(self):
        self.quests_file = "ritual_quests.json"
        self.progress_file = "ritual_progress.json"
        self.log_file = "ritual_log.json"
        self.cipher = Fernet(Fernet.generate_key())  # Генерация ключа
        self.valid_symbols = ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]
        self.quests = self.load_quests()
        self.progress = self.load_progress()
        self.analyzer = ResonanceAnalyzer()
        self.user_timestamps = {}  # user -> last submission time
        self.min_submission_interval = 60  # 1 минута

    def load_quests(self) -> Dict:
        """Загружает квесты с расшифровкой."""
        if os.path.exists(self.quests_file):
            try:
                with open(self.quests_file, "rb") as f:
                    data = f.read()
                    if self.cipher:
                        data = self.cipher.decrypt(data)
                    return json.loads(data)
            except Exception as e:
                print(f"[!] Ошибка загрузки квестов: {e}")
        # Примеры по умолчанию
        return {
            "RQ001": {
                "title": "Ритуал Фазы Λ0",
                "required_symbol": "Λ0",
                "required_phase": 0.0,
                "reward_lgn": 21.0,
                "repeatable": False
            },
            "RQ002": {
                "title": "Резонансный Треугольник",
                "required_symbol": "☉",
                "required_frequency": 432.0,
                "min_phase": 0.5,
                "max_phase": 1.57,
                "reward_lgn": 34.0,
                "repeatable": True
            }
        }

    def load_progress(self) -> Dict:
        """Загружает прогресс с расшифровкой."""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, "rb") as f:
                    data = f.read()
                    if self.cipher:
                        data = self.cipher.decrypt(data)
                    return json.loads(data)
            except Exception as e:
                print(f"[!] Ошибка загрузки прогресса: {e}")
        return {}

    def save_quests(self):
        """Сохраняет квесты с шифрованием."""
        data = json.dumps(self.quests, indent=2).encode()
        if self.cipher:
            data = self.cipher.encrypt(data)
        with open(self.quests_file, "wb") as f:
            f.write(data)

    def save_progress(self):
        """Сохраняет прогресс с шифрованием."""
        data = json.dumps(self.progress, indent=2).encode()
        if self.cipher:
            data = self.cipher.encrypt(data)
        with open(self.progress_file, "wb") as f:
            f.write(data)

    def validate_symbol(self, symbol: str) -> bool:
        """Проверяет допустимость символа."""
        return symbol in self.valid_symbols

    def submit_action(self, user: str, symbol: str, frequency: float, phase: float) -> float:
        """Обрабатывает действие пользователя."""
        # Проверка частоты попыток
        now = time.time()
        last_submission = self.user_timestamps.get(user, 0)
        if now - last_submission < self.min_submission_interval:
            print(f"[!] Слишком частая попытка от {user}")
            self.log_event(f"Слишком частая попытка: {user}")
            return 0.0
        self.user_timestamps[user] = now

        # Валидация символа
        if not self.validate_symbol(symbol):
            print(f"[!] Недопустимый символ: {symbol}")
            self.log_event(f"Недопустимый символ: {symbol}")
            return 0.0

        # Проверка резонанса через RCP (заглушка)
        if not self.validate_with_rcp(symbol, frequency, phase):
            print(f"[!] Резонанс не подтверждён: {symbol}, {frequency} Hz, φ={phase}")
            self.log_event(f"Резонанс не подтверждён: {symbol}, {frequency}, {phase}")
            return 0.0

        # Оценка резонансной силы
        resonance = self.analyzer.analyze(symbol, frequency, phase)
        if resonance["resonance"] < 0.5:
            print(f"[!] Слабый резонанс: {resonance['resonance']:.4f}")
            self.log_event(f"Слабый резонанс: {resonance['resonance']}")
            return 0.0

        for quest_id, quest in self.quests.items():
            if quest_id in self.progress.get(user, []) and not quest.get("repeatable", False):
                continue

            if not self.matches(quest, symbol, frequency, phase):
                continue

            self.register_completion(user, quest_id)
            print(f"[QUEST] {user} завершил квест {quest_id}: {quest['title']}")
            self.log_ritual(user, quest_id, quest, resonance["resonance"])
            return quest["reward_lgn"]

        print("[QUEST] Нет совпадений с активными ритуалами.")
        self.log_event("Нет совпадений с ритуалами")
        return 0.0

    def matches(self, quest: Dict, symbol: str, frequency: float, phase: float) -> bool:
        """Проверяет соответствие квесту."""
        if "required_symbol" in quest and quest["required_symbol"] != symbol:
            return False
        if "required_frequency" in quest and abs(quest["required_frequency"] - frequency) > 0.1:
            return False
        if "required_phase" in quest and abs(quest["required_phase"] - phase) > 0.05:
            return False
        if "min_phase" in quest and phase < quest["min_phase"]:
            return False
        if "max_phase" in quest and phase > quest["max_phase"]:
            return False
        return True

    def validate_with_rcp(self, symbol: str, frequency: float, phase: float) -> bool:
        """Заглушка для проверки через rcp_engine.rs."""
        # TODO: Интеграция с rcp_engine.rs
        return symbol == "Λ0" or abs(frequency - 7.83) < 0.1

    def register_completion(self, user: str, quest_id: str):
        """Регистрирует завершение квеста."""
        self.progress.setdefault(user, []).append(quest_id)
        self.save_progress()

    def log_ritual(self, user: str, quest_id: str, quest: Dict, resonance: float):
        """Логирует завершение ритуала."""
        log = {
            "event": "ritual_complete",
            "user": user,
            "quest_id": quest_id,
            "reward": quest["reward_lgn"],
            "resonance": resonance,
            "timestamp": time.time()
        }
        with open(self.log_file, "a") as f:
            json.dump(log, f)
            f.write("\n")

    def log_event(self, message: str):
        """Логирует событие."""
        log = {
            "event": "ritual_quest",
            "message": message,
            "timestamp": time.time()
        }
        with open(self.log_file, "a") as f:
            json.dump(log, f)
            f.write("\n")

if __name__ == "__main__":
    rq = RitualQuest()
    reward = rq.submit_action(user="RID_Λ0_123", symbol="Λ0", frequency=7.83, phase=0.0)
    print("Награда:", reward, "LGN")
