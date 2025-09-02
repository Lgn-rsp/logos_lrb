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
