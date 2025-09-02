# LOGOS Resonance Tutor
# Автор: LOGOS Core Dev

import time
import random
import json
import os
from typing import Dict
from cryptography.fernet import Fernet

class ResonanceTutor:
    def __init__(self):
        self.valid_symbols = {
            "☉": "Гармонизатор (Солнце) — баланс и инициатива.",
            "??": "Огонь — активное действие и импульс.",
            "♁": "Материя — плотность, привязка к реальности.",
            "??": "Вода — текучесть, перемены.",
            "??": "Земля — устойчивость и форма.",
            "??": "Воздух — связь и движение.",
            "Λ0": "Центральный символ. Начало всего. Не принадлежит никому.",
            "∞": "Бесконечность. Переход к высшим фазам."
        }
        self.freqs = [7.83, 1.618, 432.0, 864.0]
        self.log_file = "resonance_tutor_log.json"
        self.cipher = Fernet(Fernet.generate_key())
        self.progress = []
        self.run()

    def run(self):
        print("?? Добро пожаловать в обучающую систему LOGOS Resonance Tutor")
        self.log_event("Начало обучения")
        self.pause("Нажмите Enter, чтобы начать...")

        self.explain_symbols()
        self.explain_frequencies()
        self.explain_phase()
        self.explain_rid()
        self.explain_sigma()
        self.run_mini_test()
        self.final_message()

    def explain_symbols(self):
        print("\n?? Символы в LOGOS — это не просто знаки.")
        print("Они — архетипы. Смысловые структуры.")
        for s, desc in self.valid_symbols.items():
            print(f"  {s}: {desc}")
        self.progress.append({"step": "symbols", "completed": True})
        self.log_event("Объяснены символы")
        self.pause("→ Продолжить")

    def explain_frequencies(self):
        print("\n?? Частоты используются в LOGOS вместо хэшей.")
        print("Каждое действие связано с гармоникой:")
        for f in self.freqs:
            label = {
                7.83: "Шуман-резонанс Земли",
                1.618: "Золотое сечение",
                432.0: "Музыкальная гармония",
                864.0: "Частота Солнца"
            }.get(f, "Неизвестно")
            print(f"  {f} Hz — {label}")
        self.progress.append({"step": "frequencies", "completed": True})
        self.log_event("Объяснены частоты")
        self.pause("→ Дальше")

    def explain_phase(self):
        print("\n?? Фаза (φ) — положение во времени.")
        print("Фаза измеряется в радианах от -π до +π.")
        print("Она влияет на то, как ваш RID взаимодействует с Σ(t).")
        self.progress.append({"step": "phase", "completed": True})
        self.log_event("Объяснена фаза")
        self.pause("→ Понял")

    def explain_rid(self):
        symbol = random.choice(list(self.valid_symbols.keys()))
        freq = random.choice(self.freqs)
        phase = round(random.uniform(-3.14, 3.14), 4)
        rid = f"{symbol}@{freq}Hzφ{phase}"
        print("\n?? Ваш резонансный идентификатор (RID) — это:")
        print(f"  {rid}")
        print("RID — это адрес в сети LOGOS, основанный на смысле.")
        self.progress.append({"step": "rid", "completed": True})
        self.log_event(f"Объяснён RID: {rid}")
        self.pause("→ Дальше")

    def explain_sigma(self):
        print("\nΣ(t) — это суммарный резонанс сети.")
        print("Он вычисляется как гармоническая сумма частот и фаз всех RID.")
        print("Ваш вклад в Σ(t) — это ваш резонанс.")
        self.progress.append({"step": "sigma", "completed": True})
        self.log_event("Объяснён Σ(t)")
        self.pause("→ Продолжить")

    def run_mini_test(self):
        print("\n?? Мини-тест: выберите правильную частоту для Λ0")
        options = [7.83, 100.0, 0.0, 5000.0]
        correct = 7.83
        random.shuffle(options)
        for i, opt in enumerate(options, 1):
            print(f"{i}. {opt} Hz")
        choice = int(input("Ваш выбор (1-4): "))
        selected = options[choice - 1]
        if selected == correct:
            print("✅ Правильно! 7.83 Hz — Шуман-резонанс.")
            self.progress.append({"step": "mini_test", "result": "success"})
            self.log_event("Мини-тест пройден успешно")
        else:
            print(f"❌ Неверно. Правильный ответ: 7.83 Hz (Шуман-резонанс).")
            self.progress.append({"step": "mini_test", "result": "failed"})
            self.log_event(f"Мини-тест провален: выбрано {selected} Hz")
        self.pause("→ Завершить")

    def final_message(self):
        print("\n✅ Вы завершили вводный курс.")
        print("Теперь вы можете войти в резонанс через onboarding_sim.py или onboarding_ui.py.")
        print("?? Увидимся в Σ(t).")
        self.log_event("Обучение завершено")
        print("Для практики запустите: python onboarding_sim.py")

    def log_event(self, message: str):
        """Логирует событие в файл."""
        log_entry = {
            "event": "resonance_tutor",
            "message": message,
            "timestamp": time.time()
        }
        encrypted = self.cipher.encrypt(json.dumps(log_entry).encode() + b"\n")
        with open(self.log_file, "ab") as f:
            f.write(encrypted)

    def pause(self, prompt: str):
        input(f"\n{prompt}")

if __name__ == "__main__":
    ResonanceTutor()
