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
