#include <stdio.h>
#include <stdint.h>

void encrypt_byte(uint8_t *data, uint8_t key) {
    *data ^= key;
    uint8_t val = *data;
    *data = (val << 3) | (val >> 5);  // ROL 3
}

void decrypt_byte(uint8_t *data, uint8_t key) {
    uint8_t val = *data;
    val = (val >> 3) | (val << 5);  // ROR 3
    val ^= key;
    *data = val;
}

int main() {
    uint8_t test[] = {0x55, 0xAA, 0x12, 0x34};
    uint8_t key[] = {'A', 'B', 'C', 'D'};
    
    printf("Original: ");
    for (int i = 0; i < 4; i++) printf("%02x ", test[i]);
    printf("\n");
    
    // Encrypt
    for (int i = 0; i < 4; i++) {
        encrypt_byte(&test[i], key[i % 4]);
    }
    
    printf("Encrypted: ");
    for (int i = 0; i < 4; i++) printf("%02x ", test[i]);
    printf("\n");
    
    // Decrypt
    for (int i = 0; i < 4; i++) {
        decrypt_byte(&test[i], key[i % 4]);
    }
    
    printf("Decrypted: ");
    for (int i = 0; i < 4; i++) printf("%02x ", test[i]);
    printf("\n");
    
    return 0;
}
