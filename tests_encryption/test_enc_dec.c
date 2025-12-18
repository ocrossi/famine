#include <stdio.h>
#include <stdint.h>
#include <string.h>

void encrypt_buffer(uint8_t *buf, size_t size, const uint8_t *key, size_t key_size) {
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = buf[i];
        byte ^= key[i % key_size];
        byte = (byte << 3) | (byte >> 5);  // ROL 3
        buf[i] = byte;
    }
}

void decrypt_buffer(uint8_t *buf, size_t size, const uint8_t *key, size_t key_size) {
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = buf[i];
        byte = (byte >> 3) | (byte << 5);  // ROR 3
        byte ^= key[i % key_size];
        buf[i] = byte;
    }
}

int main() {
    uint8_t data[] = "Hello, World! This is a test.";
    uint8_t key[] = "SecretKey123";
    size_t len = strlen((char*)data);
    
    printf("Original: %s\n", data);
    
    encrypt_buffer(data, len, key, strlen((char*)key));
    printf("Encrypted: ");
    for (size_t i = 0; i < len; i++) printf("%02x ", data[i]);
    printf("\n");
    
    decrypt_buffer(data, len, key, strlen((char*)key));
    printf("Decrypted: %s\n", data);
    
    return 0;
}
