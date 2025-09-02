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
