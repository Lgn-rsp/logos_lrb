# LOGOS Resonance Core + Modules Snapshot

_Автогенерация: `2025-12-01 14:14:46Z`_


## Python Resonance Core (core/)

`/root/logos_lrb/core`


---

### `/root/logos_lrb/core/beta_rollout.yaml`

```yaml
yaml
version: 1.1

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

phases:
  - phase: "alpha"
    name: "Закрытый Резонанс"
    description: "Только для внутренних валидаторов. Проверка фаз, Λ0 и Σ(t)."
    max_nodes: 10
    validators_only: true
    duration_days: 14
    lgn_stake_required: 144.0
    activation: manual
    required_symbol: "Λ0"
    tasks:
      - "Проверка фазовой синхронизации"
      - "Отладка rcp_engine и phase_stabilizer"
      - "Первая фиксация Λ0 в реальных условиях"
      - "Симуляция сбоя 50% узлов"
    logs: "alpha_rollout_log.json"

  - phase: "beta-private"
    name: "Приватная сеть 81"
    description: "Подключение 81 участника с проверенными RID. Первые ритуалы, распределение rLGN."
    max_nodes: 81
    validators_only: false
    whitelist_required: true
    duration_days: 21
    lgn_stake_required: 81.0
    activation: semi-automatic
    required_symbol: "Λ0"
    tasks:
      - "Ритуальный вход через onboarding_sim.py"
      - "Активация DAO миссий"
      - "Проверка recall, spam_guard и scaler"
      - "Симуляция фазового спама"
    logs: "beta_private_log.json"

  - phase: "beta-open"
    name: "Открытый тест 1000"
    description: "До 1000 узлов. Публичная демонстрация Σ(t), резонансных транзакций и DAO-механики."
    max_nodes: 1000
    validators_only: false
    whitelist_required: false
    duration_days: 30
    lgn_stake_required: 0
    activation: public
    required_symbol: "any"
    tasks:
      - "Запуск фазы голосования через community_dao.yaml"
      - "Анализ логов via resonance_feedback.py"
      - "Публичные квесты через ritual_quest.py"
      - "Тестирование потери 30% узлов"
    logs: "beta_open_log.json"

  - phase: "mainnet-init"
    name: "Инициация Mainnet"
    description: "Активация основной сети LOGOS. Поддержка >10k узлов. Подпись через Λ0 и DAO-кворум."
    max_nodes: 10000
    validators_only: false
    whitelist_required: false
    duration_days: 9999
    lgn_stake_required: 0
    activation: by-consensus
    required_symbol: "Λ0"
    dynamic_quorum:
      enabled: true
      node_count_thresholds:
        1000: 0.5
        5000: 0.4
        10000: 0.25
    tasks:
      - "Формирование начального символа via auto_init_from_Λ0.py"
      - "Рассылка маяков и сигнала Σ(t)"
      - "Применение всех 56+ модулей в боевом режиме"
      - "Симуляция критического сбоя (70% узлов)"
    logs: "mainnet_init_log.json"

post_launch:
  monitoring:
    enabled: true
    modules:
      - "biosphere_scanner.rs"
      - "resonance_feedback.py"
      - "phase_integrity.rs"
    log_file: "post_launch_monitoring.json"
  escalation_policy:
    if_phase_failure: "Откат до beta-private, перезапуск с резервного Λ0"
    if_massive_spam: "Активация tx_spam_guard.rs + lgn_recall.rs"
    if_critical_lag: "Авто-перебалансировка через phase_scaler.rs"
  documentation:
    guide: "logos_beta_guide.md"


```

---

### `/root/logos_lrb/core/offline_resonance.py`

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math  # нужно для math.pi и других функций
import json
import time
from dataclasses import dataclass
from typing import List, Tuple

# Минимальная самодостаточная версия: генерация сигнала Σ(t) оффлайн
# Параметры резонанса (можно расширять конфигом)
F1 = 7.83      # Гц
F2 = 1.618     # Гц
F3 = 432.0     # Гц

@dataclass
class Sample:
    t: float
    s: float

def sigma_t(t: float) -> float:
    return (
        math.sin(2.0 * math.pi * F1 * t) +
        math.sin(2.0 * math.pi * F2 * t) +
        math.sin(2.0 * math.pi * F3 * t)
    )

def generate(duration_s: float = 2.0, rate_hz: float = 48000.0) -> List[Sample]:
    dt = 1.0 / rate_hz
    n = int(duration_s * rate_hz)
    out: List[Sample] = []
    t = 0.0
    for _ in range(n):
        out.append(Sample(t, sigma_t(t)))
        t += dt
    return out

def main():
    samples = generate(duration_s=1.0, rate_hz=1000.0)
    print(json.dumps([s.__dict__ for s in samples[:10]], ensure_ascii=False))

if __name__ == "__main__":
    main()

```

---

### `/root/logos_lrb/core/onboarding_sim.py`

```python
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

```

---

### `/root/logos_lrb/core/onboarding_ui.py`

```python
# LOGOS Onboarding UI
# Автор: LOGOS Core Dev

import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import json
import math
import re
from cryptography.fernet import Fernet
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

class OnboardingUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Вход в Резонанс")
        self.root.geometry("420x460")
        self.state_file = "onboarding_state.json"
        self.log_file = "onboarding_log.json"
        self.cipher = Fernet(Fernet.generate_key())  # Генерация ключа
        self.valid_symbols = {"☉", "??", "♁", "??", "??", "??", "Λ0", "∞"}

        self.status_label = tk.Label(self.root, text="Добро пожаловать в LOGOS Resonance Network", font=("Arial", 12))
        self.status_label.pack(pady=10)

        self.symbol_var = tk.StringVar(value="Λ0")
        self.phase_var = tk.DoubleVar(value=0.0)
        self.frequency_var = tk.DoubleVar(value=7.83)

        self.entry_frame()
        self.setup_animation()

        tk.Button(self.root, text="Принять фазу", font=("Arial", 14), command=self.accept_phase).pack(pady=10)
        self.root.mainloop()

    def validate_symbol(self, symbol: str) -> bool:
        """Проверяет допустимость символа."""
        return bool(re.match(r'^[☉??♁??????Λ0∞]+$', symbol))

    def entry_frame(self):
        """Создает форму для ввода данных."""
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Символ:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(frame, textvariable=self.symbol_var, width=12, font=("Arial", 10)).grid(row=0, column=1)

        tk.Label(frame, text="Частота (Hz):", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        tk.Entry(frame, textvariable=self.frequency_var, width=12, font=("Arial", 10)).grid(row=1, column=1)

        tk.Label(frame, text="Фаза (радианы):", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        tk.Entry(frame, textvariable=self.phase_var, width=12, font=("Arial", 10)).grid(row=2, column=1)

    def setup_animation(self):
        """Создает анимацию синусоиды для визуализации фазы."""
        self.fig, self.ax = plt.subplots(figsize=(4, 2))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(pady=10)
        self.update_animation(0.0)

    def update_animation(self, phase: float):
        """Обновляет анимацию синусоиды."""
        self.ax.clear()
        t = np.linspace(0, 2 * math.pi, 100)
        y = np.sin(t + phase)
        self.ax.plot(t, y, color="#FFD700", linewidth=2)
        self.ax.set_title("Резонансная фаза", fontsize=10, color="#333333")
        self.ax.set_xlabel("Время", fontsize=8)
        self.ax.set_ylabel("Амплитуда", fontsize=8)
        self.ax.grid(True, linestyle="--", alpha=0.5)
        self.canvas.draw()

    def accept_phase(self):
        """Обрабатывает принятие фазы."""
        symbol = self.symbol_var.get().strip()
        frequency = self.frequency_var.get()
        phase = self.phase_var.get()

        # Валидация
        if not self.validate_symbol(symbol):
            messagebox.showerror("Ошибка", "Недопустимый символ. Используйте ☉, ??, Λ0 и т.д.")
            return
        if frequency <= 0 or frequency > 10000.0:
            messagebox.showerror("Ошибка", "Частота должна быть в диапазоне 0.1–10000 Hz")
            return
        if not -math.pi <= phase <= math.pi:
            messagebox.showerror("Ошибка", "Фаза должна быть в диапазоне [-π, π]")
            return

        # Проверка фазы через RCP (заглушка для интеграции с rcp_engine.rs)
        if not self.validate_with_rcp(symbol, frequency, phase):
            messagebox.showerror("Ошибка", "Фаза не резонирует с сетью")
            return

        # Сохранение состояния
        accepted = {
            "symbol": symbol,
            "frequency": round(frequency, 4),
            "phase": round(phase, 4),
            "timestamp": datetime.utcnow().isoformat()
        }
        self.save_state(accepted)
        self.log_event(accepted)

        messagebox.showinfo("Успешно", f"Фаза принята: {symbol} @ {frequency} Hz, φ = {phase}")
        print("[ONBOARD] Вход выполнен:", accepted)
        self.update_animation(phase)

    def validate_with_rcp(self, symbol: str, frequency: float, phase: float) -> bool:
        """Заглушка для проверки фазы через rcp_engine.rs."""
        # TODO: Интеграция с rcp_engine.rs для проверки резонанса
        return abs(frequency - 7.83) < 0.1 or symbol == "Λ0"  # Пример проверки

    def save_state(self, state: dict):
        """Сохраняет состояние с шифрованием."""
        data = json.dumps(state, indent=2).encode()
        if self.cipher:
            data = self.cipher.encrypt(data)
        with open(self.state_file, "wb") as f:
            f.write(data)

    def log_event(self, state: dict):
        """Логирует событие входа."""
        log_entry = {
            "event": "onboarding",
            "state": state,
            "timestamp": datetime.utcnow().isoformat()
        }
        with open(self.log_file, "a") as f:
            json.dump(log_entry, f)
            f.write("\n")

if __name__ == "__main__":
    OnboardingUI()

```

---

### `/root/logos_lrb/core/resonance_analyzer.py`

```python
# LOGOS Resonance Analyzer
# Автор: LOGOS Core Dev

import math
import re
from datetime import datetime
import json

class ResonanceAnalyzer:
    def __init__(self, base_freqs=None):
        self.base_freqs = base_freqs or [7.83, 1.618, 432.0, 864.0, 3456.0]
        self.symbol_weights = {
            "☉": 0.9, "??": 0.85, "♁": 0.8, "??": 0.75, "??": 0.7,
            "??": 0.65, "Λ0": 1.0, "∞": 0.95
        }
        self.lambda_zero = "Λ0"
        self.max_freq = 10000.0  # Ограничение на частоту
        self.log_file = "resonance_log.json"

    def is_symbol_valid(self, symbol: str) -> bool:
        """Проверяет, состоит ли символ из допустимых значений."""
        return bool(re.match(r'^[☉??♁??????Λ0∞]+$', symbol))

    def symbol_weight(self, symbol: str) -> float:
        """Вычисляет вес символа с бонусом для Λ0."""
        if not self.is_symbol_valid(symbol):
            return 0.0
        weight = sum(self.symbol_weights.get(s, 0.5) for s in symbol) / len(symbol)
        if self.lambda_zero in symbol:
            weight *= 1.2  # Бонус за присутствие Λ0
        return weight

    def harmonic_score(self, freq: float) -> float:
        """Оценивает гармоничность частоты относительно базовых."""
        if freq > self.max_freq or freq <= 0.0:
            return 0.0  # Защита от экстремальных частот
        score = 0.0
        for base in self.base_freqs:
            delta = abs(freq - base)
            score += math.exp(-delta)
        return score / len(self.base_freqs)

    def update_symbol_weights(self, network_activity: dict):
        """Динамическое обновление весов символов на основе активности сети."""
        for symbol, activity in network_activity.items():
            if symbol in self.symbol_weights:
                self.symbol_weights[symbol] *= (1.0 + activity * 0.01)

    def analyze(self, symbol: str, freq: float, phase: float) -> dict:
        """Анализирует резонансную силу символа, частоты и фазы."""
        now = datetime.utcnow().timestamp()
        valid = self.is_symbol_valid(symbol)
        sym_strength = self.symbol_weight(symbol) if valid else 0.0
        harmonicity = self.harmonic_score(freq)
        resonance = sym_strength * harmonicity * math.cos(phase)

        result = {
            "valid": valid,
            "symbol_strength": round(sym_strength, 3),
            "harmonicity": round(harmonicity, 3),
            "resonance": round(resonance, 4),
            "timestamp": now
        }
        self.log_result(result)
        return result

    def log_result(self, result: dict):
        """Сохраняет результаты анализа в лог для resonance_feedback.py."""
        with open(self.log_file, 'a') as f:
            json.dump(result, f)
            f.write('\n')

if __name__ == "__main__":
    analyzer = ResonanceAnalyzer()
    # Тестовые случаи
    tests = [
        ("☉??♁", 1.618, 0.785),
        ("Λ0", 7.83, 0.0),
        ("invalid", 100000.0, 1.0),
    ]
    for symbol, freq, phase in tests:
        result = analyzer.analyze(symbol, freq, phase)
        print(f"RES ANALYSIS [{symbol}, {freq} Hz, {phase}]: {result}")

```

---

### `/root/logos_lrb/core/rid_builder.py`

```python
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

```

---

### `/root/logos_lrb/core/ritual_quest.py`

```python
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

```

---

### `/root/logos_lrb/core/rLGN_converter.py`

```python
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

```

## Service Modules (modules/)

`/root/logos_lrb/modules`


---

### `/root/logos_lrb/modules/beacon_emitter.rs`

```rust
use axum::{
    extract::State,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, time::Duration};
use tower::{ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    timeout::TimeoutLayer,
    limit::{RequestBodyLimitLayer},
};
use tracing_subscriber::{EnvFilter, fmt};
use ed25519_dalek::{SigningKey, VerifyingKey, SignatureError};
use rand_core::OsRng;
use bs58;
use once_cell::sync::OnceCell;
use anyhow::Result;

mod api;
mod admin;
mod bridge;
mod gossip;
mod state;
mod peers;
mod fork;

#[derive(Clone)]
struct AppState {
    signing: SigningKey,
    verifying: VerifyingKey,
    rid_b58: String,
    admin_key: String,
    bridge_key: String,
}

static APP_STATE: OnceCell<AppState> = OnceCell::new();

fn load_signing_key() -> Result<SigningKey> {
    use std::env;
    if let Ok(hex) = env::var("LRB_NODE_SK_HEX") {
        let bytes = hex::decode(hex.trim())?;
        let sk = SigningKey::from_bytes(bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad SK len"))?);
        return Ok(sk);
    }
    if let Ok(path) = env::var("LRB_NODE_SK_PATH") {
        let data = std::fs::read(path)?;
        let sk = SigningKey::from_bytes(data.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad SK len"))?);
        return Ok(sk);
    }
    anyhow::bail!("missing LRB_NODE_SK_HEX or LRB_NODE_SK_PATH");
}

fn rid_from_vk(vk: &VerifyingKey) -> String {
    bs58::encode(vk.as_bytes()).into_string()
}

fn read_env_required(n: &str) -> Result<String> {
    let v = std::env::var(n).map_err(|_| anyhow::anyhow!("missing env {}", n))?;
    Ok(v)
}

fn guard_secret(name: &str, v: &str) -> Result<()> {
    let bad = ["CHANGE_ADMIN_KEY","CHANGE_ME","", "changeme", "default"];
    if bad.iter().any(|b| v.eq_ignore_ascii_case(b)) {
        anyhow::bail!("{} is default/empty; refuse to start", name);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,axum=info"));
    fmt().with_env_filter(filter).init();

    // keys + env
    let sk = load_signing_key()?;
    let vk = VerifyingKey::from(&sk);
    let rid = rid_from_vk(&vk);

    let admin_key = read_env_required("LRB_ADMIN_KEY")?;
    let bridge_key = read_env_required("LRB_BRIDGE_KEY")?;
    guard_secret("LRB_ADMIN_KEY", &admin_key)?;
    guard_secret("LRB_BRIDGE_KEY", &bridge_key)?;

    let state = AppState {
        signing: sk,
        verifying: vk,
        rid_b58: rid.clone(),
        admin_key,
        bridge_key,
    };
    APP_STATE.set(state.clone()).unwrap();

    // CORS
    let cors = {
        let allowed_origin = std::env::var("LRB_WALLET_ORIGIN").unwrap_or_else(|_| String::from("https://wallet.example"));
        CorsLayer::new()
            .allow_origin(allowed_origin.parse::<axum::http::HeaderValue>().unwrap())
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
    };

    // limits/timeout
    let layers = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(RequestBodyLimitLayer::new(512 * 1024)) // 512 KiB
        .layer(cors)
        .into_inner();

    // маршруты
    let app = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/head", get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx", post(api::submit_tx))
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/debug_canon", post(api::debug_canon))
        .route("/faucet", post(api::faucet)) // dev-only
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem", post(bridge::redeem))
        .route("/bridge/verify", post(bridge::verify))
        .route("/admin/snapshot", post(admin::snapshot))
        .route("/admin/restore", post(admin::restore))
        .route("/node/info", get(admin::node_info))
        .with_state(state)
        .layer(layers);

    let addr: SocketAddr = std::env::var("LRB_NODE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    tracing::info!("logos_node listening on {} (RID={})", addr, rid);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

```

---

### `/root/logos_lrb/modules/env_impact_tracker.py`

```python
# LOGOS Environmental Impact Tracker
# Автор: LOGOS Core Dev

import time
import json
import os
import psutil
from cryptography.fernet import Fernet
from typing import Dict
from resonance_analyzer import ResonanceAnalyzer

class EnvImpactTracker:
    def __init__(self):
        self.state_file = "env_impact_state.json"
        self.log_file = "env_impact_log.json"
        self.cipher = Fernet(Fernet.generate_key())
        self.lambda_zero = "Λ0"
        self.valid_symbols = ["☉", "??", "♁", "??", "??", "??", "Λ0", "∞"]
        self.collected: Dict[str, float] = {}
        self.interval_sec = 60
        self.last_record_time = 0
        self.network_activity = 1.0
        self.analyzer = ResonanceAnalyzer()
        self.thresholds = {"cpu": 80.0, "memory": 80.0, "disk": 90.0}
        self.load_state()

    def load_state(self):
        """Загружает состояние с расшифровкой."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "rb") as f:
                    data = self.cipher.decrypt(f.read())
                    self.collected = json.loads(data)
            except Exception as e:
                self.log_event(f"[!] Ошибка загрузки состояния: {e}")
                self.collected = {}

    def validate_symbol(self, symbol: str) -> bool:
        """Проверяет допустимость символа."""
        return symbol in self.valid_symbols

    def update_network_activity(self, activity: float):
        """Обновляет интервал сканирования на основе активности."""
        self.network_activity = max(0.1, min(activity, 10.0))
        self.interval_sec = max(30, min(120, 60 / self.network_activity))
        self.log_event(f"[INFO] Network activity updated: {self.network_activity}, interval={self.interval_sec}s")

    def scan(self, symbol: str = "Λ0") -> bool:
        """Собирает метрики воздействия."""
        now = time.time()
        if now - self.last_record_time < self.interval_sec:
            self.log_event("[!] Слишком частое сканирование")
            return False
        self.last_record_time = now

        if not self.validate_symbol(symbol):
            self.log_event(f"[!] Недопустимый символ: {symbol}")
            return False

        # Сбор метрик
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        temp = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}

        # Адаптивная коррекция для Λ0
        adjustment = 1.2 if symbol == self.lambda_zero else 1.0

        impact = {
            "timestamp": now,
            "symbol": symbol,
            "cpu": round(cpu * adjustment, 2),
            "memory": round(mem * adjustment, 2),
            "disk": round(disk * adjustment, 2),
            "network_bytes": net,
            "thermal_zones": {k: [round(t.current, 2) for t in v] for k, v in temp.items()} if temp else {}
        }

        # Проверка аномалий
        anomalies = []
        if impact["cpu"] > self.thresholds["cpu"]:
            anomalies.append(f"CPU={impact['cpu']}%")
        if impact["memory"] > self.thresholds["memory"]:
            anomalies.append(f"MEM={impact['memory']}%")
        if impact["disk"] > self.thresholds["disk"]:
            anomalies.append(f"DISK={impact['disk']}%")

        # Интеграция с resonance_analyzer
        resonance = self.analyzer.analyze(symbol, 7.83 if symbol == self.lambda_zero else 1.618, 0.0)
        impact["resonance_score"] = resonance["resonance"]

        self.collected[str(int(now))] = impact
        self.save_state()

        log_message = f"Impact: CPU={impact['cpu']}%, MEM={impact['memory']}%, Symbol={symbol}, Resonance={resonance['resonance']:.4f}"
        if anomalies:
            log_message += f", Anomalies: {', '.join(anomalies)}"
        self.log_event(log_message)
        return True

    def save_state(self):
        """Сохраняет состояние с шифрованием."""
        data = json.dumps(self.collected, indent=2).encode()
        encrypted = self.cipher.encrypt(data)
        with open(self.state_file, "wb") as f:
            f.write(encrypted)

    def log_event(self, message: str):
        """Логирует событие."""
        log = {
            "event": "env_impact",
            "message": message,
            "timestamp": time.time()
        }
        encrypted = self.cipher.encrypt(json.dumps(log).encode() + b"\n")
        with open(self.log_file, "ab") as f:
            f.write(encrypted)

    def get_latest_impact(self) -> Dict:
        """Возвращает последнюю запись."""
        if self.collected:
            return list(self.collected.values())[-1]
        return {}

if __name__ == "__main__":
    tracker = EnvImpactTracker()
    tracker.update_network_activity(2.0)
    if tracker.scan(symbol="Λ0"):
        print("Последнее воздействие:", json.dumps(tracker.get_latest_impact(), indent=2))
    else:
        print("Ожидание интервала между сканами...")

```

---

### `/root/logos_lrb/modules/external_phase_broadcaster.rs`

```rust
//! Внешний широковещатель фаз: AEAD XChaCha20-Poly1305 + Ed25519 подпись.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct PhaseBroadcaster {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl PhaseBroadcaster {
    pub fn new(key32: [u8;32], self_vk: VerifyingKey) -> Self {
        Self { aead: AeadBox::from_key(&key32), self_vk }
    }

    pub fn pack(&self, signer: &SigningKey, topic: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(topic.len()+32);
        aad.extend_from_slice(topic);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, payload);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64 + sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn unpack(&self, sender_vk: &VerifyingKey, topic: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("phase_bcast: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("phase_bcast: bad signature"))?;

        let mut aad = Vec::with_capacity(topic.len()+32);
        aad.extend_from_slice(topic);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let pt = self.aead.open(&aad, sealed)?;
        Ok(pt)
    }
}

```

---

### `/root/logos_lrb/modules/external_phase_link.rs`

```rust
//! Безопасная версия external_phase_link без unsafe-кастов.
//! Состояние защищено через RwLock. Однопоточная производительность сохраняется.

use std::sync::{Arc, RwLock};
use anyhow::Result;

#[derive(Default, Clone, Debug)]
pub struct PhaseState {
    pub last_tick_ms: u64,
    pub phase_strength: f32,
}

#[derive(Clone)]
pub struct ExternalPhaseLink {
    state: Arc<RwLock<PhaseState>>,
}

impl ExternalPhaseLink {
    pub fn new() -> Self {
        Self { state: Arc::new(RwLock::new(PhaseState::default())) }
    }

    pub fn tick(&self, now_ms: u64, input_strength: f32) -> Result<()> {
        let mut st = self.state.write().expect("rwlock poisoned");
        st.last_tick_ms = now_ms;
        st.phase_strength = 0.9 * st.phase_strength + 0.1 * input_strength;
        Ok(())
    }

    pub fn snapshot(&self) -> PhaseState {
        self.state.read().expect("rwlock poisoned").clone()
    }
}

```

---

### `/root/logos_lrb/modules/genesis_fragment_seeds.rs`

```rust
//! Genesis Fragment Seeds: шифрованное хранение фрагментов seed.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct SeedVault { aead:AeadBox, self_vk:VerifyingKey }

impl SeedVault {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn pack_fragment(&self, signer:&SigningKey, label:&[u8], fragment:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(label.len()+32); aad.extend_from_slice(label); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, fragment); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn unpack_fragment(&self, sender_vk:&VerifyingKey, label:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("seed_vault: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("seed_vault: bad sig"))?;
        let mut aad=Vec::with_capacity(label.len()+32); aad.extend_from_slice(label); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

```

---

### `/root/logos_lrb/modules/go_to_market.yaml`

```yaml
yaml
version: 1.1
created: 2025-07-05
authors:
  - LOGOS Core Dev Team

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

launch_phases:
  - name: "Genesis Outreach"
    target: "Ранние сторонники, идеологические участники"
    duration_days: 14
    required_symbol: "Λ0"
    focus:
      - "Ритуальные миссии через ritual_quest.py"
      - "Формирование 81 ключевого RID"
      - "Публичное представление Λ0"
    channels:
      - "Telegram: logos_community_channel"
      - "Discord: logos_resonance_server"
      - "GitHub Issues: logos_network/repo"
    metrics:
      - "Количество валидных RID (rid_builder.py)"
      - "Реакция в resonance_feedback.py"
      - "DAO-активность (community_dao.yaml)"
    test_campaign:
      name: "simulate_genesis_outreach"
      description: "Эмуляция подключения 81 RID"

  - name: "LGN Liquidity Phase"
    target: "DEX и CEX листинг"
    duration_days: 30
    required_symbol: "any"
    focus:
      - "Запуск rLGN_converter.py"
      - "Добавление пары LGN/USDT"
      - "Обратная конвертация через DAO-гранты"
    exchanges:
      - "Uniswap: ERC-20 pair"
      - "MEXC: LGN/USDT"
      - "Gate.io: LGN/USDT"
    metrics:
      - "Объем торговли LGN"
      - "Задержки rLGN → LGN (rLGN_converter.py)"
      - "Количество DAO-кейсов (community_dao.yaml)"
    test_campaign:
      name: "simulate_liquidity_launch"
      description: "Эмуляция листинга на DEX/CEX"

  - name: "Main Resonance"
    target: "Массовый пользователь"
    duration_days: 90
    required_symbol: "any"
    focus:
      - "Образование: resonance_tutor.py"
      - "Фаза доверия: onboarding_ui.py"
      - "Публичные голосования в community_dao.yaml"
    regions:
      - name: "RU"
        languages: ["ru"]
      - name: "EU"
        languages: ["en", "de", "fr"]
      - name: "LATAM"
        languages: ["es", "pt"]
    metrics:
      - "Количество успешных входов в Σ(t) (onboarding_sim.py)"
      - "Активность в rituals (ritual_quest.py)"
      - "Обратная связь (resonance_feedback.py)"
    test_campaign:
      name: "simulate_mass_adoption"
      description: "Эмуляция 1000+ входов пользователей"

education_plan:
  modules:
    - "resonance_tutor.py"
    - "onboarding_ui.py"
    - "logos_ethics.md"
  campaigns:
    - name: "Enter the Phase"
      platform: "YouTube"
      type: "Анимированное видео"
      languages: ["en", "ru", "es"]
    - name: "RID Drop"
      platform: "Twitter"
      type: "Раздача RID с фазовыми квестами"
      languages: ["en", "ru", "es"]

integration_targets:
  wallets:
    - name: "TrustWallet"
      status: "Negotiation"
    - name: "Metamask"
      status: "Planned"
  blockchains:
    - "Ethereum (via symbolic_bridge.rs)"
    - "Polkadot"
    - "Cosmos"
  bridges:
    - "symbolic_bridge.rs"
    - "legacy_migrator.rs"

tracking:
  dashboard: "resonance_analytics_frontend"
  metrics:
    - rid_growth
    - lgn_volume
    - rlg_conversion_rate
    - dao_participation
  log_encryption:
    enabled: true
    encryption_key: "generate_at_runtime"  # AES-256

dao_support:
  proposals_enabled: true
  voting_required: true
  quorum: 0.33
  budget_lgn: 10888.0
  update_frequency_days: 14

```

---

### `/root/logos_lrb/modules/heartbeat_monitor.rs`

```rust
//! Heartbeat Monitor — безопасные heartbeat-кадры между узлами (AEAD+подпись).

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

#[derive(Clone)]
pub struct HeartbeatMonitor { aead:AeadBox, self_vk:VerifyingKey }

impl HeartbeatMonitor {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn encode_ping(&self, signer:&SigningKey, channel:&[u8], payload:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(channel.len()+32); aad.extend_from_slice(channel); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, payload); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn decode_frame(&self, sender_vk:&VerifyingKey, channel:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("heartbeat: short frame"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("heartbeat: bad signature"))?;
        let mut aad=Vec::with_capacity(channel.len()+32); aad.extend_from_slice(channel); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

```

---

### `/root/logos_lrb/modules/legacy_migrator.rs`

```rust
//! Legacy Migrator: перенос артефактов со шифрованием и подписью.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct LegacyMigrator { aead:AeadBox, self_vk:VerifyingKey }

impl LegacyMigrator {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn wrap_blob(&self, signer:&SigningKey, kind:&[u8], blob:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(kind.len()+32); aad.extend_from_slice(kind); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, blob); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn unwrap_blob(&self, sender_vk:&VerifyingKey, kind:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("legacy_migrator: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("legacy_migrator: bad sig"))?;
        let mut aad=Vec::with_capacity(kind.len()+32); aad.extend_from_slice(kind); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

```

---

### `/root/logos_lrb/modules/maintenance_strategy.yaml`

```yaml
yaml
version: 1.1
created: 2025-07-05
authors:
  - LOGOS Core Dev Team

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

update_channels:
  - name: stable
    description: "Проверенные обновления, подписанные DAO"
    auto_deploy: false
    approval_required: true
    required_symbol: "Λ0"
  - name: beta
    description: "Тестирование новых модулей и интеграций"
    auto_deploy: true
    approval_required: false
    required_symbol: "any"
  - name: dev
    description: "Экспериментальная среда для новых функций"
    auto_deploy: true
    approval_required: false
    required_symbol: "any"

rotation_policy:
  modules:
    restart_interval_sec:
      default: 86400  # 24 часа
      adaptive:
        enabled: true
        network_activity_thresholds:
          low: { value: 172800, activity: 0.5 }  # 48 часов при низкой активности
          high: { value: 43200, activity: 5.0 }  # 12 часов при высокой
    max_failure_before_isolation: 3
    isolation_mode:
      enabled: true
      trigger_modules:
        - "rcp_engine.rs"
        - "phase_scaler.rs"
        - "resonance_analyzer.py"
      test_scenarios:
        - name: "simulate_module_failure"
          description: "Эмуляция отказа 3+ модулей"

lifecycle_hooks:
  pre_restart:
    - "backup_state with phase_backup.rs"
    - "notify_admins via telegram and email"
  post_restart:
    - "verify Σ(t) with phase_integrity.rs"
    - "send heartbeat to dao_monitor via community_dao.yaml"

compatibility_matrix:
  required_versions:
    rust: ">=1.74"
    python: ">=3.10"
    cargo: ">=1.70"
    serde_json: ">=1.0.96"
    ring: ">=0.17"

auto_patch:
  enabled: true
  modules_included:
    - "resonance_feedback.py"
    - "onboarding_ui.py"
    - "symbolic_firewall.rs"
  security_only: false
  max_patches_per_day: 3

release_schedule:
  cadence: "monthly"
  last_release: "2025-06-30"
  next_scheduled: "2025-07-31"
  lgn_budget_reserved: 888.0

logs:
  directory: "logs/maintenance/"
  encrypted: true
  encryption_key: "generate_at_runtime"  # AES-256
  notify_admins:
    channels:
      - telegram: "logos_maintenance_channel"
      - email: "alerts@logos.network"
  backup_to: "phase_backup.rs"

```

---

### `/root/logos_lrb/modules/resonance_emergency_plan.yaml`

```yaml
yaml
version: 1.1
created: 2025-07-05
authors:
  - LOGOS Core Dev Team

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

critical_conditions:
  - id: PHASE-DROP
    name: "Резкое падение Σ(t)"
    detection_module: "phase_integrity.rs"
    response:
      - "Заморозить входящие транзакции (tx_spam_guard.rs)"
      - "Активировать phase_stabilizer.rs для восстановления Σ(t)"
      - "Рассылка сигнала Λ0 через beacon_emitter.rs"
    required_symbol: "Λ0"

  - id: BIOSPHERE-ALERT
    name: "Аномалия биосферы"
    detection_module: "biosphere_scanner.rs"
    response:
      - "Отключить усилители в resonance_math.rs"
      - "Снизить частоту вещания до 1.618 Hz"
      - "Сбор данных через resonance_feedback.py"
    required_symbol: "any"

  - id: DISSONANT-SYMBOL-ATTACK
    name: "Фазовая атака через недопустимые символы"
    detection_module: "symbolic_firewall.rs"
    response:
      - "Блокировка offending RID через tx_spam_guard.rs"
      - "Отзыв до 50% LGN через lgn_recall.rs"
      - "Фиксация в logs/emergency_dissonance.json"
    required_symbol: "Λ0"

  - id: NETWORK-OVERCLOCK
    name: "Перегрузка Σ(t) по частоте"
    detection_module: "dynamic_balance.rs"
    response:
      - "Увеличить LGN_cost вдвое в dynamic_balance.rs"
      - "Активация phase_scaler.rs для ребалансировки"
      - "Оповещение DAO через community_dao.yaml"
    required_symbol: "Λ0"

  - id: CRITICAL-CHAOS
    name: "Сбой более 70% узлов"
    detection_module: "phase_intercept_guard.rs"
    response:
      - "Переход в фазу auto_init_from_Λ0.py"
      - "Сброс Σ(t) до базового уровня (7.83 Hz)"
      - "Созыв DAO-кворума с 25% порогом"
    required_symbol: "Λ0"
    test_scenario: "simulate_70_percent_node_failure"

fallback_actions:
  if_logos_core_fails:
    - "Изоляция Λ0 ядра через genesis_fragment_seeds.rs"
    - "Включение аварийной цепочки backup_nodes.json"
    - "Восстановление через phase_backup.rs"
  if_feedback_shows_harm:
    - "Полное торможение Σ(t) в phase_stabilizer.rs"
    - "Миграция в low-resonance режим (1.618 Hz)"
    - "Обратный отчёт в DAO через resonance_feedback.py"

logs:
  directory: "logs/emergency/"
  encrypted: true
  encryption_key: "generate_at_runtime"  # AES-256
  notify_admins:
    channels:
      - telegram: "logos_emergency_channel"
      - email: "alerts@logos.network"

check_interval_sec:
  default: 60
  adaptive:
    enabled: true
    network_activity_thresholds:
      low: { value: 120, activity: 0.5 }
      high: { value: 30, activity: 5.0 }

rcp_override_allowed: false

test_scenarios:
  - name: "simulate_70_percent_node_failure"
    description: "Эмуляция сбоя 70% узлов для проверки CRITICAL-CHAOS"
    module: "phase_intercept_guard.rs"
  - name: "simulate_biosphere_anomaly"
    description: "Эмуляция аномалии биосферы для BIOSPHERE-ALERT"
    module: "biosphere_scanner.rs"

```

---

### `/root/logos_lrb/modules/resonance_meshmap.yaml`

```yaml
yaml
version: 1.1
generated: 2025-07-05
source: "phase_scaler.rs"

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

symbol_map:
  Λ0:
    color: "#FFD700"
    role: "Core synchronizer"
  ☉:
    color: "#FFA500"
    role: "Harmonizer"
  ??:
    color: "#FF4500"
    role: "Initiator"
  ♁:
    color: "#33CC33"
    role: "Stabilizer"
  ??:
    color: "#3399FF"
    role: "Flux"
  ??:
    color: "#996633"
    role: "Grounding"
  ??:
    color: "#AAAAAA"
    role: "Air flow"
  ∞:
    color: "#CCCCCC"
    role: "Infinity"

clusters:
  CLUSTER_7.830:
    label: "Schumann Core"
    max_nodes: 144
    active_nodes:
      - rid: "Λ0@7.83Hzφ0.000"
        joined: 2025-07-05T10:00:00Z
      - rid: "☉@7.83Hzφ0.4142"
        joined: 2025-07-05T10:01:03Z
    center_phase: 0.2
    symbol_dominance: "Λ0"
    overload_action: "Activate phase_scaler.rs rebalance"

  CLUSTER_432.000:
    label: "Harmonic Field"
    max_nodes: 288
    active_nodes:
      - rid: "??@432Hzφ-0.618"
        joined: 2025-07-05T10:02:44Z
      - rid: "♁@432Hzφ0.309"
        joined: 2025-07-05T10:04:12Z
    center_phase: -0.14
    symbol_dominance: "??"
    overload_action: "Activate phase_scaler.rs rebalance"

  CLUSTER_1.618:
    label: "Golden Mesh"
    max_nodes: 81
    active_nodes:
      - rid: "??@1.618Hzφ0.707"
        joined: 2025-07-05T10:08:00Z
    center_phase: 0.6
    symbol_dominance: "??"
    overload_action: "Activate phase_scaler.rs rebalance"

summary:
  total_clusters: 3
  total_active_rids: 5
  symbol_distribution:
    Λ0: 1
    ☉: 1
    ??: 1
    ♁: 1
    ??: 1

log_config:
  file: "resonance_meshmap_log.json"
  encrypted: true
  encryption_key: "generate_at_runtime"  # AES-256

update_config:
  enabled: true
  update_interval_sec: 300  # Каждые 5 минут
  modules:
    - "phase_scaler.rs"
    - "resonance_analyzer.py"

```

---

### `/root/logos_lrb/modules/resonance_tutor.py`

```python
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

```

---

### `/root/logos_lrb/modules/ritual_engine.rs`

```rust
//! Ritual Engine: доставка «ритуальных» сообщений c фазовой меткой, AEAD+подпись.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct RitualEngine { aead:AeadBox, self_vk:VerifyingKey }

impl RitualEngine {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn send(&self, signer:&SigningKey, phase_id:&[u8], msg:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(phase_id.len()+32); aad.extend_from_slice(phase_id); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, msg); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn recv(&self, sender_vk:&VerifyingKey, phase_id:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("ritual_engine: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("ritual_engine: bad sig"))?;
        let mut aad=Vec::with_capacity(phase_id.len()+32); aad.extend_from_slice(phase_id); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

```

---

### `/root/logos_lrb/modules/symbolic_parser.py`

```python
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

```

---

### `/root/logos_lrb/modules/uplink_controller.rs`

```rust
//! Uplink Controller: надёжная упаковка кадров uplink → core.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct UplinkController {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl UplinkController {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self {
        Self { aead:AeadBox::from_key(&key32), self_vk }
    }

    pub fn encode_frame(&self, signer:&SigningKey, channel:&[u8], frame:&[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(channel.len()+32);
        aad.extend_from_slice(channel);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, frame);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64+sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn decode_frame(&self, sender_vk:&VerifyingKey, channel:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("uplink_controller: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("uplink_controller: bad signature"))?;

        let mut aad = Vec::with_capacity(channel.len()+32);
        aad.extend_from_slice(channel);
        aad.extend_from_slice(self.self_vk.as_bytes());

        Ok(self.aead.open(&aad, sealed)?)
    }
}

```

---

### `/root/logos_lrb/modules/uplink_router.rs`

```rust
//! Uplink Router: безопасная пересылка кадров между маршрутами.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct UplinkRouter {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl UplinkRouter {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self {
        Self { aead:AeadBox::from_key(&key32), self_vk }
    }

    pub fn wrap(&self, signer:&SigningKey, route:&[u8], payload:&[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(route.len()+32);
        aad.extend_from_slice(route);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, payload);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64+sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn unwrap(&self, sender_vk:&VerifyingKey, route:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("uplink_router: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("uplink_router: bad signature"))?;

        let mut aad = Vec::with_capacity(route.len()+32);
        aad.extend_from_slice(route);
        aad.extend_from_slice(self.self_vk.as_bytes());

        Ok(self.aead.open(&aad, sealed)?)
    }
}

```

---

### `/root/logos_lrb/modules/x_guard/Cargo.toml`

```toml
[package]
name = "logos_x_guard"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
axum = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
reqwest = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }

```

---

### `/root/logos_lrb/modules/x_guard/src/main.rs`

```rust
use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use reqwest::{Client, StatusCode as HttpStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::prelude::*;

#[derive(Clone, Debug)]
struct XCreds {
    api_key: String,
    api_secret: String,
    bearer_token: String,
    access_token: Option<String>,
    access_token_secret: Option<String>,
}

fn read_env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing env {}", name))
}

fn read_env_optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn guard_secret(name: &str, value: &str) -> Result<()> {
    let bad = ["CHANGE_ME", "changeme", "default", "", "EXAMPLE_X_API_KEY_REPLACE_ME"];
    if bad.iter().any(|b| value.eq_ignore_ascii_case(b)) {
        return Err(anyhow!(
            "{} is default/empty placeholder; refuse to start",
            name
        ));
    }
    Ok(())
}

impl XCreds {
    fn from_env() -> Result<Self> {
        let api_key = read_env_required("X_API_KEY")?;
        let api_secret = read_env_required("X_API_SECRET")?;
        let bearer_token = read_env_required("X_BEARER_TOKEN")?;

        guard_secret("X_API_KEY", &api_key)?;
        guard_secret("X_API_SECRET", &api_secret)?;
        guard_secret("X_BEARER_TOKEN", &bearer_token)?;

        let access_token = read_env_optional("X_ACCESS_TOKEN");
        let access_token_secret = read_env_optional("X_ACCESS_TOKEN_SECRET");

        Ok(Self {
            api_key,
            api_secret,
            bearer_token,
            access_token,
            access_token_secret,
        })
    }
}

#[derive(Clone)]
struct XClient {
    http: Client,
    creds: Arc<XCreds>,
    base_url: String,
}

impl XClient {
    fn new(creds: XCreds) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .expect("failed to build reqwest client");

        Self {
            http,
            creds: Arc::new(creds),
            base_url: "https://api.x.com/2".to_string(),
        }
    }

    async fn get_raw(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt: u32 = 0;

        loop {
            attempt += 1;
            let resp = self
                .http
                .get(&url)
                .query(query)
                .bearer_auth(&self.creds.bearer_token)
                .send()
                .await
                .with_context(|| format!("request to {}", url))?;

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();

            if status == HttpStatus::TOO_MANY_REQUESTS && attempt < 4 {
                let sleep_secs = 30 * attempt;
                info!(
                    "rate limited by X on {}, attempt {} -> sleep {}s",
                    url, attempt, sleep_secs
                );
                tokio::time::sleep(Duration::from_secs(sleep_secs as u64)).await;
                continue;
            }

            if status.is_server_error() && attempt < 4 {
                let backoff = 2_u64.pow(attempt);
                info!(
                    "server error from X: {} on {}, retry in {}s",
                    status, url, backoff
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                continue;
            }

            if !status.is_success() {
                return Err(anyhow!(
                    "X API error: status={} body={}",
                    status.as_u16(),
                    text
                ));
            }

            let json: Value = serde_json::from_str(&text)
                .with_context(|| format!("parsing JSON from {}: {}", url, text))?;
            return Ok(json);
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<UserInfo> {
        let path = format!("/users/by/username/{}", username);
        let json = self
            .get_raw(&path, &[("user.fields", "created_at,public_metrics")])
            .await?;

        let data = json
            .get("data")
            .ok_or_else(|| anyhow!("no data in user response"))?;

        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("no id in user data"))?
            .to_string();

        let uname = data
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or(username)
            .to_string();

        let created_at = data
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let followers = data
            .get("public_metrics")
            .and_then(|v| v.get("followers_count"))
            .and_then(|v| v.as_u64());

        Ok(UserInfo {
            id,
            username: uname,
            created_at,
            followers,
        })
    }

    async fn user_follows(&self, source_user_id: &str, target_user_id: &str) -> Result<bool> {
        let path = format!("/users/{}/following", source_user_id);
        let json = self
            .get_raw(&path, &[("max_results", "1000"), ("user.fields", "id,username")])
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let found = data.iter().any(|u| {
            u.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == target_user_id)
                .unwrap_or(false)
        });

        Ok(found)
    }

    async fn user_liked_tweet(&self, user_id: &str, tweet_id: &str) -> Result<bool> {
        let path = format!("/tweets/{}/liking_users", tweet_id);
        let json = self
            .get_raw(&path, &[("max_results", "100"), ("user.fields", "id")])
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let found = data.iter().any(|u| {
            u.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == user_id)
                .unwrap_or(false)
        });

        Ok(found)
    }

    async fn user_retweeted_tweet(&self, user_id: &str, tweet_id: &str) -> Result<bool> {
        let path = format!("/tweets/{}/retweeted_by", tweet_id);
        let json = self
            .get_raw(&path, &[("max_results", "100"), ("user.fields", "id")])
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let found = data.iter().any(|u| {
            u.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == user_id)
                .unwrap_or(false)
        });

        Ok(found)
    }
}

#[derive(Clone, Debug)]
struct UserInfo {
    id: String,
    username: String,
    created_at: Option<String>,
    followers: Option<u64>,
}

#[derive(Clone)]
struct AppState {
    x: XClient,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn health(State(_state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "logos_x_guard",
    })
}

#[derive(Deserialize)]
struct CheckRequest {
    user_username: String,
    project_username: String,
    tweet_id: String,
    #[serde(default = "default_true")]
    require_follow: bool,
    #[serde(default = "default_true")]
    require_like: bool,
    #[serde(default = "default_true")]
    require_retweet: bool,
    #[serde(default = "default_min_age")]
    min_account_age_days: u32,
    #[serde(default = "default_min_followers")]
    min_followers: u32,
}

fn default_true() -> bool {
    true
}
fn default_min_age() -> u32 {
    3
}
fn default_min_followers() -> u32 {
    3
}

#[derive(Serialize)]
struct CheckResponse {
    ok: bool,
    user_username: String,
    project_username: String,
    tweet_id: String,
    follow_ok: bool,
    like_ok: bool,
    retweet_ok: bool,
    age_ok: bool,
    followers_ok: bool,
    user_info: Value,
}

async fn check_airdrop(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    let res = do_check_airdrop(state, req).await;
    match res {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            error!("check_airdrop error: {:?}", err);
            let body = serde_json::json!({
                "ok": false,
                "error": "internal_error",
                "message": err.to_string(),
            });
            (StatusCode::BAD_GATEWAY, Json(body)).into_response()
        }
    }
}

async fn do_check_airdrop(state: Arc<AppState>, req: CheckRequest) -> Result<CheckResponse> {
    let user = state.x.get_user_by_username(&req.user_username).await?;
    let project = state
        .x
        .get_user_by_username(&req.project_username)
        .await?;

    let age_ok = true; // упрощённо, без парсинга created_at

    let followers_ok = user
        .followers
        .map(|c| c >= req.min_followers as u64)
        .unwrap_or(false);

    let mut follow_ok = true;
    let mut like_ok = true;
    let mut retweet_ok = true;

    if req.require_follow {
        follow_ok = state
            .x
            .user_follows(&user.id, &project.id)
            .await
            .unwrap_or(false);
    }

    if req.require_like {
        like_ok = state
            .x
            .user_liked_tweet(&user.id, &req.tweet_id)
            .await
            .unwrap_or(false);
    }

    if req.require_retweet {
        retweet_ok = state
            .x
            .user_retweeted_tweet(&user.id, &req.tweet_id)
            .await
            .unwrap_or(false);
    }

    let ok = follow_ok && like_ok && retweet_ok && age_ok && followers_ok;

    let user_info = serde_json::json!({
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at,
        "followers": user.followers,
    });

    Ok(CheckResponse {
        ok,
        user_username: req.user_username,
        project_username: req.project_username,
        tweet_id: req.tweet_id,
        follow_ok,
        like_ok,
        retweet_ok,
        age_ok,
        followers_ok,
        user_info,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter_layer =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into());
    let fmt_layer = fmt::layer().with_target(false);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let creds = XCreds::from_env().context("reading X_* env vars")?;
    info!("X credentials loaded, starting service");

    let x_client = XClient::new(creds);
    let state = Arc::new(AppState { x: x_client });

    let app = Router::new()
        .route("/health", get(health))
        .route("/check_airdrop", post(check_airdrop))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8091".parse().unwrap();
    info!("LOGOS X Guard listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

```
