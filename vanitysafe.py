#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VanitySafe — офлайн-аудитор префиксов "красивых" адресов.
Поддержка цепей: ETH (hex), BTC (Base58 P2PKH/Bech32, упрощенная оценка), SOL (Base58).

Функции:
- Оценка потери энтропии от фиксированного префикса
- Оценка ожидаемого числа попыток/времени подбора на заданной скорости
- Предупреждения о фишинговых рисках (похожие символы, словоформы)
- Отчёт в консоль и/или JSON

Примеры:
  python vanitysafe.py analyze --chain eth --prefix 0xABCD
  python vanitysafe.py analyze --chain btc --prefix 1Kid
  python vanitysafe.py analyze --chain sol --prefix SoL0 --rate 5e7 --json out.json
"""

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
except ImportError:
    Console = None
    Table = None
    Text = None
    Panel = None

# ======= Константы =======

HEX_ALPHABET = "0123456789abcdef"
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # без 0OIl
BECH32_HRP_SET = {"bc", "tb"}  # упрощённо: mainnet/testnet hrp для BTC
LOG2_58 = math.log2(58)

PHISHY_LOOKALIKES = [
    ("0", "O"),
    ("1", "l"),
    ("5", "S"),
    ("2", "Z"),
    ("8", "B"),
    ("6", "G"),
]

# Мини-словарь слов/брендов, которые часто используют в vanity и которые могут повышать социальные риски
WORDLIST_FLAG = {
    "bank", "coin", "crypto", "safe", "secure", "trust", "swap", "airdrop",
    "elon", "vitalik", "tesla", "binance", "okx", "bybit", "kraken",
    "send", "pay", "gift", "donate", "help", "human", "aid",
    "sol", "btc", "eth", "nft", "mint", "pump",
}


# ======= Модель результата =======

@dataclass
class AnalysisResult:
    chain: str
    prefix: str
    normalized_prefix: str
    fixed_symbols: int
    entropy_loss_bits: float
    total_space_factor: float
    expected_trials: float
    est_seconds_cpu: Optional[float]
    est_seconds_gpu: Optional[float]
    warnings: List[str]


# ======= Утилиты =======

def human_time(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    if seconds < 1e-6:
        return f"{seconds*1e9:.2f} ns"
    if seconds < 1e-3:
        return f"{seconds*1e6:.2f} µs"
    if seconds < 1:
        return f"{seconds*1e3:.2f} ms"
    units = [("s", 60), ("min", 60), ("h", 24), ("d", 365/12), ("mo", 12), ("y", 1e9)]
    value = seconds
    names = ["s", "min", "h", "d", "mo", "y"]
    thresholds = [60, 60, 24, 30, 12]
    for i, (name, base) in enumerate(units[:-1]):
        if value < base:
            return f"{value:.2f} {name}"
        value /= base
    return f"{value:.2f} y"


def human_trials(x: float) -> str:
    if x < 1000:
        return f"{x:.2f}"
    units = ["", "K", "M", "B", "T", "Q"]
    i = 0
    while x >= 1000 and i < len(units) - 1:
        x /= 1000.0
        i += 1
    return f"{x:.2f} {units[i]}"


def looks_phishy(prefix: str) -> List[str]:
    warns = []
    # похожие символы
    for a, b in PHISHY_LOOKALIKES:
        if a in prefix and b in prefix:
            warns.append(f"В префиксе встречаются похожие символы «{a}» и «{b}» — риск визуальной путаницы.")
    # словоформы/бренды
    low = prefix.lower()
    for w in WORDLIST_FLAG:
        if w in low:
            warns.append(f"Обнаружено слово «{w}» — повышенный социальный риск (подделки/фишинг).")
    # повторяющиеся паттерны
    if re.search(r"(.)\1\1\1", prefix):
        warns.append("4+ одинаковых символа подряд — легко подделать, высока вероятность конфузов.")
    return warns


# ======= Расчёты по цепям =======

def analyze_eth(prefix: str, rate_cpu: float, rate_gpu: float) -> AnalysisResult:
    # Нормализуем: убираем 0x, приводим к нижнему регистру
    raw = prefix
    p = prefix.lower()
    if p.startswith("0x"):
        p = p[2:]
    # допустим только [0-9a-f]
    hx = re.sub(r"[^0-9a-f]", "", p)
    fixed_nibbles = len(hx)
    entropy_loss = 4.0 * fixed_nibbles
    expected_trials = 2 ** entropy_loss  # вероятность совпадения = 1/16^k
    warnings = looks_phishy(raw)
    if fixed_nibbles > 10:
        warnings.append("Очень длинный hex-префикс — может быть непрактично даже на GPU.")
    return AnalysisResult(
        chain="ETH",
        prefix=raw,
        normalized_prefix="0x" + hx if hx else "—",
        fixed_symbols=fixed_nibbles,
        entropy_loss_bits=entropy_loss,
        total_space_factor=expected_trials,
        expected_trials=expected_trials,
        est_seconds_cpu=expected_trials / rate_cpu if rate_cpu else None,
        est_seconds_gpu=expected_trials / rate_gpu if rate_gpu else None,
        warnings=warnings,
    )


def analyze_btc(prefix: str, rate_cpu: float, rate_gpu: float) -> AnalysisResult:
    """
    Упрощённая модель:
    - Если префикс начинается с '1' (P2PKH), считаем фиксированными символами всё ПОСЛЕ первой '1'.
    - Если начинается с 'bc1' (bech32), считаем фиксированными символами всё ПОСЛЕ 'bc1'.
    - Иначе — считаем все символы как фиксацию в Base58/Bech32 строке.
    Это приближённо: реальные распределения зависят от версии, длины и кодирования, но для оценки годится.
    """
    raw = prefix
    p = prefix.strip()

    # detect bech32
    prefix_lower = p.lower()
    bech = False
    fixed_chars = 0
    if prefix_lower.startswith("bc1") or prefix_lower.startswith("tb1"):
        bech = True
        fixed_chars = max(0, len(p) - 3)  # после 'bc1'/'tb1'
    elif p.startswith("1"):
        # P2PKH mainnet обычно на '1'
        fixed_chars = max(0, len(p) - 1)
    else
        :
        fixed_chars = len(p)

    # Модель: каждая фиксированная позиция ~ 1/58
    entropy_loss = fixed_chars * LOG2_58
    expected_trials = 2 ** entropy_loss

    warnings = looks_phishy(raw)
    if fixed_chars >= 6:
        warnings.append("Префикс для BTC довольно длинный — генерация может занять значительное время.")

    hrp = "bc1..." if bech else "1..."
    return AnalysisResult(
        chain=f"BTC ({'Bech32' if bech else 'Base58'})",
        prefix=raw,
        normalized_prefix=hrp + p[len("bc1"):] if bech else ("1" + p[1:] if p.startswith("1") else p),
        fixed_symbols=fixed_chars,
        entropy_loss_bits=entropy_loss,
        total_space_factor=expected_trials,
        expected_trials=expected_trials,
        est_seconds_cpu=expected_trials / rate_cpu if rate_cpu else None,
        est_seconds_gpu=expected_trials / rate_gpu if rate_gpu else None,
        warnings=warnings,
    )


def analyze_sol(prefix: str, rate_cpu: float, rate_gpu: float) -> AnalysisResult:
    raw = prefix
    p = re.sub(rf"[^{re.escape(B58_ALPHABET)}]", "", prefix)
    fixed_chars = len(p)
    entropy_loss = fixed_chars * LOG2_58
    expected_trials = 2 ** entropy_loss
    warnings = looks_phishy(raw)
    if fixed_chars > 7:
        warnings.append("Очень длинный Base58 префикс — даже быстрые генераторы будут искать долго.")
    return AnalysisResult(
        chain="SOL",
        prefix=raw,
        normalized_prefix=p if p else "—",
        fixed_symbols=fixed_chars,
        entropy_loss_bits=entropy_loss,
        total_space_factor=expected_trials,
        expected_trials=expected_trials,
        est_seconds_cpu=expected_trials / rate_cpu if rate_cpu else None,
        est_seconds_gpu=expected_trials / rate_gpu if rate_gpu else None,
        warnings=warnings,
    )


# ======= Рендер =======

def render_console(results: List[AnalysisResult], rate_cpu: float, rate_gpu: float):
    if Console is None or Table is None:
        # Фоллбэк: простой вывод
        print(f"CPU rate: {rate_cpu:.2e} addr/s, GPU rate: {rate_gpu:.2e} addr/s")
        for r in results:
            print(f"\n[{r.chain}] {r.prefix}")
            print(f"  Нормализация: {r.normalized_prefix}")
            print(f"  Фикс. символов: {r.fixed_symbols}")
            print(f"  Потеря энтропии: {r.entropy_loss_bits:.2f} бит")
            print(f"  Ожидаемо попыток: {human_trials(r.expected_trials)}")
            print(f"  Время (CPU): {human_time(r.est_seconds_cpu)}  |  (GPU): {human_time(r.est_seconds_gpu)}")
            for w in r.warnings:
                print(f"  ⚠ {w}")
        return

    console = Console()
    header = Panel.fit(
        Text("VanitySafe — аудит префиксов vanity-адресов", justify="center", style="bold"),
        border_style="cyan"
    )
    console.print(header)
    console.print(f"Скорости: CPU ≈ {rate_cpu:.2e} addr/s, GPU ≈ {rate_gpu:.2e} addr/s\n")

    table = Table(title="Результаты", expand=True)
    table.add_column("Цепь")
    table.add_column("Префикс")
    table.add_column("Нормализация")
    table.add_column("Фикс. симв.")
    table.add_column("Потеря, бит")
    table.add_column("Попыток ~")
    table.add_column("CPU время")
    table.add_column("GPU время")

    for r in results:
        table.add_row(
            r.chain,
            r.prefix,
            r.normalized_prefix,
            str(r.fixed_symbols),
            f"{r.entropy_loss_bits:.2f}",
            human_trials(r.expected_trials),
            human_time(r.est_seconds_cpu),
            human_time(r.est_seconds_gpu),
        )

    console.print(table)

    # Warnings
    for r in results:
        if r.warnings:
            console.print(Panel.fit(
                Text("\n".join(f"• {w}" for w in r.warnings), style="yellow"),
                title=f"Предупреждения: {r.chain} / {r.prefix}",
                border_style="yellow",
            ))


def write_json(results: List[AnalysisResult], path: str, meta: Dict):
    payload = {
        "meta": meta,
        "results": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


# ======= CLI =======

def main():
    parser = argparse.ArgumentParser(
        description="VanitySafe — офлайн-аудит префиксов vanity-адресов (ETH/BTC/SOL)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Проанализировать один или несколько префиксов")
    a.add_argument("--chain", choices=["eth", "btc", "sol"], required=True, help="Цепь")
    a.add_argument("--prefix", action="append", required=True,
                   help="Префикс адреса (можно указать несколько через повтор флага)")
    a.add_argument("--rate", type=float, default=None,
                   help="Скорость генерации адресов addr/s (перезапишет CPU/GPU дефолты)")
    a.add_argument("--rate-cpu", type=float, default=5e5, help="CPU addr/s (по умолчанию ~500k)")
    a.add_argument("--rate-gpu", type=float, default=5e7, help="GPU addr/s (по умолчанию ~50M)")
    a.add_argument("--json", type=str, default=None, help="Сохранить отчёт в JSON по указанному пути")

    args = parser.parse_args()

    rate_cpu = args.rate if args.rate is not None else args.rate_cpu
    rate_gpu = args.rate if args.rate is not None else args.rate_gpu

    analyzers = {
        "eth": analyze_eth,
        "btc": analyze_btc,
        "sol": analyze_sol,
    }

    results: List[AnalysisResult] = []
    for pfx in args.prefix:
        res = analyzers[args.chain](pfx, rate_cpu, rate_gpu)
        results.append(res)

    render_console(results, rate_cpu, rate_gpu)

    if args.json:
        meta = {
            "chain": args.chain,
            "rate_cpu": rate_cpu,
            "rate_gpu": rate_gpu,
            "version": "0.1.0",
        }
        write_json(results, args.json, meta)
        if Console:
            Console().print(f"\n[green]JSON отчёт сохранён в:[/green] {args.json}")
        else:
            print(f"\nJSON отчёт сохранён в: {args.json}")


if __name__ == "__main__":
    main()
