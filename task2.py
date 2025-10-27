import json
import time
import hashlib
import math
from typing import List

class HyperLogLog:
    def __init__(self, p: int = 14):
        # p: Precision parameter (from 4 to 16).
        # m = 2^p: Number of registers (buckets). The larger m, the more accurate, but more memory.
        self.p = p
        self.m = 1 << p

        self.registers = [0] * self.m

        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1 + 1.079 / self.m)

    def _hash(self, item: str) -> int:
        hash_bytes = hashlib.sha1(item.encode('utf-8')).digest()
        return int.from_bytes(hash_bytes[:8], byteorder='big')

    def add(self, item: str):
        hashed_value = self._hash(item)
        register_index = hashed_value & (self.m - 1)

        hash_tail = hashed_value >> self.p

        if hash_tail == 0:
            rho = 64 - self.p
        else:
            rho = (hash_tail & -hash_tail).bit_length()

        self.registers[register_index] = max(self.registers[register_index], rho)

    def count(self) -> float:
        harmonic_mean = 0
        for rho in self.registers:
            harmonic_mean += 2 ** (-rho)

        estimation = self.alpha * self.m * self.m / harmonic_mean

        if estimation < 2.5 * self.m:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)
            else:
                return estimation

        return estimation


def extract_ip_addresses(log_lines) -> List[str]:
    ip_addresses = []

    for i, line in enumerate(log_lines):
        try:
            # Load JSON from line
            log_entry = json.loads(line)

            # Extract IP address
            if "remote_addr" in log_entry:
                ip = log_entry["remote_addr"].strip()
                # Filter empty or invalid IPs
                if ip:
                    ip_addresses.append(ip)
        except json.JSONDecodeError:
            # Ignore invalid lines
            # print(f"Warning: Failed to decode JSON on line {i+1}")
            continue

    return ip_addresses


def exact_unique_count(ips: List[str]) -> int:
    return len(set(ips))


def compare_counting_performance(ips: List[str]):
    HLL_PRECISION = 14
    # -----------------------------------------------------
    # Stage 1: Exact count (Set)
    # -----------------------------------------------------
    start_time_exact = time.time()
    exact_count_result = exact_unique_count(ips)
    end_time_exact = time.time()
    time_exact = end_time_exact - start_time_exact

    # -----------------------------------------------------
    # Stage 2: Approximate count (HyperLogLog)
    # -----------------------------------------------------
    start_time_hll = time.time()
    hll_filter = HyperLogLog(p=HLL_PRECISION)

    for ip in ips:
        hll_filter.add(ip)

    hll_count_result = hll_filter.count()
    end_time_hll = time.time()
    time_hll = end_time_hll - start_time_hll

    # -----------------------------------------------------
    # Output results
    # -----------------------------------------------------

    print("📋 Comparison results: HyperLogLog vs. Exact count")
    print("-" * 55)
    print(f"Total number of log entries: {len(ips)}")
    output = f"""
                       Exact count   HyperLogLog (p={HLL_PRECISION})
Unique elements      {exact_count_result:<16.0f}{hll_count_result:<16.1f}
Execution time (sec.)   {time_exact:<16.4f}{time_hll:<16.4f}
    """
    print(output)

    # Additional information about accuracy
    error = abs(exact_count_result - hll_count_result)
    relative_error = (error / exact_count_result) * 100 if exact_count_result else 0
    print(f"📊 Absolute HLL error: {error:.1f}")
    print(f"📊 Relative HLL error: {relative_error:.2f}%")


def read_file_without_newlines(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.read().split('\n')
            return lines
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []


if __name__ == "__main__":
    print("\n💡 Starting file reading")
    full_log_content = read_file_without_newlines('lms-stage-access.log')
    print("\n💡 File was parsed")

    all_ips = extract_ip_addresses(full_log_content)
    compare_counting_performance(all_ips)