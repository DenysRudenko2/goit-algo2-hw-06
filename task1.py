import array
import hashlib

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        if size <= 0 or num_hashes <= 0:
            raise ValueError("Size and number of hashes must be positive.")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = array.array('B', [0]) * (size // 8 + 1)

    def _get_hashes(self, item: str) -> list[int]:
        item_bytes = item.encode('utf-8')

        h1 = int(hashlib.sha256(item_bytes).hexdigest(), 16)
        h2 = int(hashlib.md5(item_bytes).hexdigest(), 16)

        indices = []
        for i in range(self.num_hashes):
            index = (h1 + i * h2) % self.size # Formula: h(x) = (h1 + i * h2) mod size
            indices.append(index)

        return indices

    def add(self, item: str) -> None:
        if not isinstance(item, str) or not item:
            return

        for index in self._get_hashes(item):
            byte_index = index // 8
            bit_position = index % 8

            self.bit_array[byte_index] |= (1 << bit_position)

    def contains(self, item: str) -> bool:
        if not isinstance(item, str) or not item:
            return False

        for index in self._get_hashes(item):
            byte_index = index // 8
            bit_position = index % 8

            if not (self.bit_array[byte_index] & (1 << bit_position)):
                return False

        return True

def check_password_uniqueness(bloom_filter: BloomFilter, new_passwords: list[str]) -> dict[str, str]:
    results = {}

    for password in new_passwords:
        if not password:
            continue

        is_potentially_used = bloom_filter.contains(password)

        if is_potentially_used:
            status = "already used"
        else:
            status = "unique"
            bloom_filter.add(password)

        results[password] = status

    return results

if __name__ == "__main__":
    # Initialize Bloom filter
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Add existing passwords
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Check new passwords
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Print results
    for password, status in results.items():
        print(f"Password '{password}' - {status}.")