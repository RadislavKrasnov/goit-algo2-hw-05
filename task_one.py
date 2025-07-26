import mmh3

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or not isinstance(num_hashes, int):
            raise TypeError("Size and number of hashes must be integers")
        
        if size <= 0 or num_hashes <= 0:
            raise ValueError("Size and number of hashes must be positive")
        
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    
    def add(self, item: str) -> None:
        if not isinstance(item, str):
            raise TypeError("Only strings can be added to BloomFilter")
        
        for i in range(self.num_hashes):
            index = mmh3.hash(item, i) % self.size
            self.bit_array[index] = 1


    def contains(self, item: str) -> bool:
        if not isinstance(item, str):
            return False
        
        for i in range(self.num_hashes):
            index = mmh3.hash(item, i) % self.size
            if self.bit_array[index] == 0:
                return False
        return True


def check_password_uniqueness(bloom: BloomFilter, passwords: list) -> dict:
    results = {}
    for pw in passwords:
        if not isinstance(pw, str) or pw == "":
            results[pw] = 'invalid value'
        
        if bloom.contains(pw):
            results[pw] = 'вже використаний'
        else:
            results[pw] = 'унікальний'
    return results

if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
