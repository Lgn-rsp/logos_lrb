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
