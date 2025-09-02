# LOGOS Onboarding Simulator
# Автор: LOGOS Core Dev

import time
import math
import json
import os
from typing import Dict
from cryptography.fernet import Fernet
from resonance_analyzer import ResonanceAnalyzer  # Импорт для оценки резонанса

class OnboardingSimulator:
    def __init__(self):
        self.state_file = "onboarding_sim_state.json"
        self.log_file = "onboarding_sim_log.json"
        self.cipher = Fernet(Fernet.generate_key())  # Генерация ключа шифрования
        self.valid_symbols = ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]  # Синхронизация с другими модулями
        self.phases = [0.0, math.pi / 4, math.pi / 2, math.pi, -math.pi / 2]
        self.freqs = [7.83, 1.618, 432.0]
        self.progress = []
        self.analyzer = ResonanceAnalyzer()  # Для оценки резонансной силы

    def run(self):
        print("Добро пожаловать в симулятор резонанса LOGOS.")
        print("Вы пройдёте 3 этапа: Символ → Частота → Фаза")
        input("Нажмите Enter для начала...\n")

        self.choose_symbol()
        self.choose_frequency()
        self.choose_phase()
        self.finalize()

    def choose_symbol(self):
        print("\nШаг 1: Выбор символа (архетипа)")
        for i, s in enumerate(self.valid_symbols):
            print(f"{i + 1}. {s}")
        index = self.ask_choice(len(self.valid_symbols))
        chosen = self.valid_symbols[index - 1]
        self.progress.append({"step": "symbol", "value": chosen})
        self.log_event(f"Выбран символ: {chosen}")
        print(f"Вы выбрали: {chosen}")

    def choose_frequency(self):
        print("\nШаг 2: Выбор частоты (гармоники)")
        for i, f in enumerate(self.freqs):
            print(f"{i + 1}. {f} Hz")
        index = self.ask_choice(len(self.freqs))
        chosen = self.freqs[index - 1]
        self.progress.append({"step": "frequency", "value": chosen})
        self.log_event(f"Выбрана частота: {chosen} Hz")
        print(f"Вы выбрали: {chosen} Hz")

    def choose_phase(self):
        print("\nШаг 3: Выбор фазы (φ)")
        for i, p in enumerate(self.phases):
            label = f"{round(p, 3)} рад" if p != 0.0 else "0 (идеальная фаза)"
            print(f"{i + 1}. {label}")
        index = self.ask_choice(len(self.phases))
        chosen = self.phases[index - 1]
        self.progress.append({"step": "phase", "value": round(chosen, 4)})
        self.log_event(f"Выбрана фаза: φ = {chosen:.4f}")
        print(f"Вы выбрали фазу: φ = {chosen:.4f}")

    def finalize(self):
        print("\n✅ Симуляция завершена!")
        result = {
            "symbol": self.progress[0]["value"],
            "frequency": self.progress[1]["value"],
            "phase": self.progress[2]["value"],
            "timestamp": time.time()
        }
        # Оценка резонансной силы
        resonance = self.analyzer.analyze(
            result["symbol"], result["frequency"], result["phase"]
        )
        result["resonance_score"] = resonance["resonance"]
        self.save_state(result)
        self.log_event(f"Резонанс: {resonance['resonance']:.4f}")
        print("Результат сохранён в:", self.state_file)
        print(f"Сила резонанса: {resonance['resonance']:.4f}")
        print("Теперь вы готовы к настоящему резонансу!")
        # Заглушка для RCP проверки
        if self.validate_with_rcp(result):
            print("[RCP] Резонанс подтверждён сетью!")
        else:
            print("[RCP] Резонанс не подтверждён. Попробуйте изменить параметры.")

    def validate_with_rcp(self, result: Dict) -> bool:
        """Заглушка для проверки через rcp_engine.rs."""
        # TODO: Интеграция с rcp_engine.rs
        return result["resonance_score"] > 0.5 and result["symbol"] == "Λ0"

    def save_state(self, state: Dict):
        """Сохраняет состояние с шифрованием."""
        data = json.dumps(state, indent=2).encode()
        if self.cipher:
            data = self.cipher.encrypt(data)
        with open(self.state_file, "wb") as f:
            f.write(data)

    def log_event(self, message: str):
        """Логирует событие в файл."""
        log_entry = {
            "event": "onboarding_sim",
            "message": message,
            "timestamp": time.time()
        }
        with open(self.log_file, "a") as f:
            json.dump(log_entry, f)
            f.write("\n")

    def ask_choice(self, max_choice: int) -> int:
        while True:
            try:
                choice = int(input("Ваш выбор: "))
                if 1 <= choice <= max_choice:
                    return choice
                else:
                    print(f"Введите число от 1 до {max_choice}")
            except:
                print("Ошибка ввода. Попробуйте снова.")

if __name__ == "__main__":
    sim = OnboardingSimulator()
    sim.run()
