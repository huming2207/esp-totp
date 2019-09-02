#pragma once

class otp
{
    public:
        static uint32_t hotp_generate(uint8_t *key, size_t key_len, uint64_t interval, size_t digits);
        static uint32_t totp_hash_token(uint8_t *key, size_t key_len, uint64_t time, size_t digits);
        static uint32_t totp_generate(uint8_t *key, size_t key_len);

    private:
        static void hotp_hmac(unsigned char *key, size_t ken_len, uint64_t interval, uint8_t *out);
        static uint32_t hotp_dt(const uint8_t *digest);
};

