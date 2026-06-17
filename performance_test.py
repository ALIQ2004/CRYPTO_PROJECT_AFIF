"""
Performance testing for the symmetric cryptography group project.

This program creates three test files:
1. 1 KB
2. 100 KB
3. 1 MB

Then, it measures encryption and decryption time for:
1. LFSR-based Stream Cipher
2. AES-CBC Block Cipher

The program outputs:
1. results/performance_results.csv
2. results/encryption_time_comparison.png
"""

from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import Callable

import matplotlib.pyplot as plt

from crypto_project import AESCBC, LFSRConfig, LFSRStreamCipher, create_test_file


BASE_DIR = Path(__file__).resolve().parent.parent
TEST_DIR = BASE_DIR / "test_files"
RESULT_DIR = BASE_DIR / "results"

TEST_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(exist_ok=True)

FILE_SIZES = {
    "1 KB": 1 * 1024,
    "100 KB": 100 * 1024,
    "1 MB": 1024 * 1024,
}


def measure_seconds(function: Callable, *args) -> tuple[float, bytes]:
    """Measure the execution time of an encryption/decryption function."""
    start_time = time.perf_counter()
    output = function(*args)
    end_time = time.perf_counter()

    elapsed_time = end_time - start_time
    return elapsed_time, output


def run_tests() -> list[dict[str, str | int | float]]:
    """Run performance tests for all file sizes and algorithms."""
    rows = []

    for file_label, size_bytes in FILE_SIZES.items():
        file_name = f"test_{file_label.replace(' ', '_')}.bin"
        file_path = TEST_DIR / file_name

        create_test_file(file_path, size_bytes)
        original_data = file_path.read_bytes()

        # =====================================================
        # LFSR STREAM CIPHER TEST
        # =====================================================
        lfsr_seed = LFSRStreamCipher.generate_key()

        lfsr_encryptor = LFSRStreamCipher(LFSRConfig(seed=lfsr_seed))
        lfsr_encryption_time, lfsr_ciphertext = measure_seconds(
            lfsr_encryptor.encrypt,
            original_data
        )

        lfsr_decryptor = LFSRStreamCipher(LFSRConfig(seed=lfsr_seed))
        lfsr_decryption_time, lfsr_plaintext = measure_seconds(
            lfsr_decryptor.decrypt,
            lfsr_ciphertext
        )

        assert lfsr_plaintext == original_data, "LFSR decryption output does not match original file."

        rows.append({
            "file_size": file_label,
            "size_bytes": size_bytes,
            "algorithm": "LFSR Stream Cipher",
            "encryption_time_sec": lfsr_encryption_time,
            "decryption_time_sec": lfsr_decryption_time,
        })

        # =====================================================
        # AES-CBC BLOCK CIPHER TEST
        # =====================================================
        aes_key = AESCBC.generate_key()

        aes_encryption_time, aes_ciphertext = measure_seconds(
            AESCBC.encrypt,
            original_data,
            aes_key
        )

        aes_decryption_time, aes_plaintext = measure_seconds(
            AESCBC.decrypt,
            aes_ciphertext,
            aes_key
        )

        assert aes_plaintext == original_data, "AES-CBC decryption output does not match original file."

        rows.append({
            "file_size": file_label,
            "size_bytes": size_bytes,
            "algorithm": "AES-CBC",
            "encryption_time_sec": aes_encryption_time,
            "decryption_time_sec": aes_decryption_time,
        })

    return rows


def save_csv(rows: list[dict[str, str | int | float]]) -> Path:
    """Save performance test results into a CSV file."""
    csv_path = RESULT_DIR / "performance_results.csv"

    with csv_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "file_size",
                "size_bytes",
                "algorithm",
                "encryption_time_sec",
                "decryption_time_sec",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    return csv_path


def create_graph(rows: list[dict[str, str | int | float]]) -> Path:
    """Create a bar chart comparing encryption time."""
    labels = list(FILE_SIZES.keys())
    algorithms = ["LFSR Stream Cipher", "AES-CBC"]

    x_positions = range(len(labels))
    bar_width = 0.35

    plt.figure(figsize=(8, 5))

    for index, algorithm in enumerate(algorithms):
        encryption_times = []

        for label in labels:
            matching_row = next(
                row for row in rows
                if row["file_size"] == label and row["algorithm"] == algorithm
            )
            encryption_times.append(float(matching_row["encryption_time_sec"]))

        bar_positions = [x + (index - 0.5) * bar_width for x in x_positions]
        plt.bar(bar_positions, encryption_times, width=bar_width, label=algorithm)

    plt.xlabel("File Size")
    plt.ylabel("Encryption Time (seconds)")
    plt.title("Encryption Time Comparison: LFSR Stream Cipher vs AES-CBC")
    plt.xticks(list(x_positions), labels)
    plt.legend()
    plt.tight_layout()

    graph_path = RESULT_DIR / "encryption_time_comparison.png"
    plt.savefig(graph_path, dpi=180)
    plt.close()

    return graph_path


def print_results(rows: list[dict[str, str | int | float]]) -> None:
    """Print results in a readable format for checking."""
    print("\nPerformance Test Results")
    print("=" * 80)

    for row in rows:
        print(
            f"{row['file_size']:>6} | "
            f"{row['algorithm']:<20} | "
            f"Encryption: {float(row['encryption_time_sec']):.8f}s | "
            f"Decryption: {float(row['decryption_time_sec']):.8f}s"
        )

    print("=" * 80)


if __name__ == "__main__":
    results = run_tests()
    csv_file = save_csv(results)
    graph_file = create_graph(results)
    print_results(results)

    print(f"\nCSV saved to: {csv_file}")
    print(f"Graph saved to: {graph_file}")
