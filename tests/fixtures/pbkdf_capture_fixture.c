#include <CommonCrypto/CommonKeyDerivation.h>
#include <stdint.h>
#include <unistd.h>

int main(void) {
    uint8_t password[32];
    uint8_t salt[16];
    uint8_t key[32];
    for (uint8_t index = 0; index < 32; index++) password[index] = index;
    for (uint8_t index = 0; index < 16; index++) salt[index] = index;
    int result = CCKeyDerivationPBKDF(
        kCCPBKDF2,
        (const char *)password,
        sizeof(password),
        salt,
        sizeof(salt),
        kCCPRFHmacAlgSHA512,
        256000,
        key,
        sizeof(key)
    );
    sleep(2);
    return result;
}
