import json
import time
import mmh3
import math

class HyperLogLog:
    def __init__(self, p: int = 14):
        if not isinstance(p, int) or p <= 0:
            raise ValueError("Precision parameter p must be a positive integer")
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_threshold = 5 * self.m / 2

    
    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)
        
    
    def add(self, item: str) -> None:
        x = mmh3.hash(item, signed=False) & 0xFFFFFFFF
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    
    def _rho(self, w: int) -> int:
        bit_len = 32 - self.p
        if w == 0:
            return bit_len + 1
        return (bit_len - w.bit_length()) + 1
    

    def count(self):
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z
        
        if E <= self.small_range_threshold:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)
        
        return E
    
def load_ips():
    with open('lms-stage-access.log', 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            if not line:
                continue

            try:
                record = json.loads(line)
                ip = record.get('remote_addr')

                if ip and isinstance(ip, str):
                    yield ip
            except json.JSONDecodeError:
                continue


def exact_count_ips() -> tuple[int, float]:
    unique_ips = set()
    start = time.perf_counter()

    for ip in load_ips():
        unique_ips.add(ip)
    
    end = time.perf_counter()
    return len(unique_ips), end - start
    

def hll_count_ips() -> tuple[int, float]:
    hll = HyperLogLog()
    start = time.perf_counter()
    
    for ip in load_ips():
        hll.add(ip)

    estimate = hll.count()
    end = time.perf_counter()
    
    return estimate, end - start


def main():
    exact_count, exact_time = exact_count_ips()
    hll_estimate, hll_time = hll_count_ips()

    print("\nРезультати порівняння:")
    print(f"{'':<30}{'Точний підрахунок':>20}{'HyperLogLog':>20}")
    print(f"{'Унікальні елементи':<30}{exact_count:>20,.1f}{hll_estimate:>20,.1f}")
    print(f"{'Час виконання (сек.)':<30}{exact_time:>20.3f}{hll_time:>20.3f}")

if __name__ == '__main__':
    main()
