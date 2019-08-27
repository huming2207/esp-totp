#include <ctime>
#include <cmath>
#include <mbedtls/md.h>
#include <sys/types.h>

#include "otp.hpp"

/**
 * Generate HMAC-based One Time Password token
 * @param key Key issued by the service providers
 * @param key_len Key length
 * @param interval Valid interval
 * @param digits Digits in length
 * @return OTP token
 */
uint32_t otp::hotp_generate(uint8_t *key, size_t key_len, uint64_t interval, size_t digits)
{
    uint8_t *digest = nullptr;
    uint32_t endianness;

    // Endianness detection
    endianness = 0xdeadbeef;
    if ((*(const uint8_t *)&endianness) == 0xef) {
        interval = ((interval & 0x00000000ffffffffU) << 32u) | ((interval & 0xffffffff00000000U) >> 32u);
        interval = ((interval & 0x0000ffff0000ffffU) << 16u) | ((interval & 0xffff0000ffff0000U) >> 16u);
        interval = ((interval & 0x00ff00ff00ff00ffU) <<  8u) | ((interval & 0xff00ff00ff00ff00U) >>  8u);
    };

    // First Phase, get the digest of the message using the provided key ...
    hotp_hmac(key, key_len, interval, digest);

    // Second Phase, get the dbc from the algorithm
    uint32_t dbc = hotp_dt(digest);

    // Third Phase: calculate the mod_k of the dbc to get the correct number
    int power = (int)pow(10, digits);
    uint32_t otp = dbc % power;

    return otp;
}

/**
 * Generate TOTP token
 * @param key OTP key issued by service providers
 * @param key_len Key length
 * @param time Current time
 * @param digits Digit amount of the token generated
 * @return TOTP token
 */
uint32_t otp::totp_hash_token(uint8_t *key, size_t key_len, uint64_t time, size_t digits)
{
    return hotp_generate(key, key_len, time, digits);
}

/**
 * Generate common (Google/Microsoft) style TOTP token based on system time
 *  The token is:
 *      - 6 digits long
 *      - valid in the recent 30 seconds
 * @param key OTP key issued by the service providers
 * @param key_len Key length
 * @return TOTP token
 */
uint32_t otp::totp_generate(uint8_t *key, size_t key_len)
{
    auto timestamp = (time_t)floor(time(nullptr) / 30.0);
    return totp_hash_token(key, key_len, timestamp, 6);
}

/**
 * Base32 decoder
 * From https://github.com/google/google-authenticator-libpam/blob/master/src/base32.c
 * @param encoded Encoded text
 * @param result Bytes output
 * @param buf_len Bytes length
 * @return -1 if failed, or length decoded
 */
int otp::base32_decode(const char *encoded, uint8_t *result, int buf_len)
{
    int buffer = 0;
    int bits_left = 0;
    int count = 0;
    for (const char *ptr = encoded; count < buf_len && *ptr; ++ptr) {
        uint8_t ch = *ptr;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
            continue;
        }
        buffer <<= 5;

        // Deal with commonly mistyped characters
        if (ch == '0') {
            ch = 'O';
        } else if (ch == '1') {
            ch = 'L';
        } else if (ch == '8') {
            ch = 'B';
        }

        // Look up one base32 digit
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            ch = (ch & 0x1F) - 1;
        } else if (ch >= '2' && ch <= '7') {
            ch -= '2' - 26;
        } else {
            return -1;
        }

        buffer |= ch;
        bits_left += 5;
        if (bits_left >= 8) {
            result[count++] = buffer >> (bits_left - 8);
            bits_left -= 8;
        }
    }
    if (count < buf_len) {
        result[count] = '\000';
    }
    return count;
}

/**
 * Base32 encoder
 * From https://github.com/google/google-authenticator-libpam/blob/master/src/base32.c
 * @param data Bytes input
 * @param length Length of the bytes to be encoded
 * @param result Result string in Base32
 * @param encode_len Maximum length of the string
 * @return -1 if failed, or the length encoded
 */
int otp::base32_encode(const uint8_t *data, int length, char *result, int encode_len)
{
    if (length < 0 || length > (1 << 28)) {
        return -1;
    }
    int count = 0;
    if (length > 0) {
        int buffer = data[0];
        int next = 1;
        int bits_left = 8;
        while (count < encode_len && (bits_left > 0 || next < length)) {
            if (bits_left < 5) {
                if (next < length) {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bits_left += 8;
                } else {
                    int pad = 5 - bits_left;
                    buffer <<= pad;
                    bits_left += pad;
                }
            }
            int index = 0x1F & (buffer >> (bits_left - 5));
            bits_left -= 5;
            result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
        }
    }

    if (count < encode_len) {
        result[count] = '\000';
    }

    return count;
}

void otp::hotp_hmac(unsigned char *key, size_t ken_len, uint64_t interval, uint8_t *out)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, ken_len);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *) &interval, sizeof(interval));
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

uint32_t otp::hotp_dt(const uint8_t *digest)
{
    uint64_t offset;
    uint32_t bin_code;

    // dynamically truncates hash
    offset   = digest[19] & 0x0fU;

    bin_code = (digest[offset] & 0x7fU) << 24u
               | (digest[offset+1u] & 0xffU) << 16u
               | (digest[offset+2u] & 0xffU) << 8u
               | (digest[offset+3u] & 0xffU);

    return bin_code;
}

