#include "key_uri.hpp"

#include <utility>
#include <esp_log.h>
#include <cstring>

#define TAG "uri_parser"

key_uri::key_uri(std::string _uri) : uri(std::move(_uri))
{
}

esp_err_t key_uri::parse()
{
    std::string_view _uri(uri);

    // Step 1: Probe the schema. If success, move to the 10th char (remove "otpauth://")
    ESP_LOGD(TAG, "Parsing schema...");
    if(_uri.find("otpauth://") == std::string_view::npos) return ESP_ERR_INVALID_ARG;
    _uri = _uri.substr(10);

    // Step 2: Parse type
    ESP_LOGD(TAG, "Parsing type...");
    auto type_str = _uri.substr(0, 4);
    if(type_str == "totp") time_based = true;
    else if(type_str == "hotp") time_based = false;
    else return ESP_ERR_INVALID_ARG;
    _uri = _uri.substr(5); // Skip "[h,t]otp/"

    // Step 3: Parse provider label
    ESP_LOGD(TAG, "Parsing label...");
    auto label_end = _uri.find('?');
    if(label_end == std::string_view::npos) return ESP_ERR_INVALID_ARG;
    auto label_raw = _uri.substr(0, label_end);
    ESP_LOGD(TAG, "Got label: %s", label_raw.data());
    label = decode_uri(label_raw);
    _uri = _uri.substr(label_end);

    // Step 4: Parse each of the "query parameters"
    // Secret
    ESP_LOGD(TAG, "Parsing secret...");
    secret = get_query_val(_uri, "secret");

    // Issuer
    ESP_LOGD(TAG, "Parsing issuer...");
    issuer = decode_uri(get_query_val(_uri, "issuer"));

    // Counter (for HOTP only)
    ESP_LOGD(TAG, "Parsing counter...");
    if(!time_based) counter = std::strtol(get_query_val(_uri, "counter").data(), nullptr, 10);

    // Interval/Period
    ESP_LOGD(TAG, "Parsing interval...");
    interval = std::strtol(get_query_val(_uri, "period").data(), nullptr, 10);
    if(interval < 1) return ESP_ERR_INVALID_ARG;

    // Digits
    ESP_LOGD(TAG, "Parsing digits...");
    digits = std::strtol(get_query_val(_uri, "digits").data(), nullptr, 10);
    if(digits < 6) return ESP_ERR_INVALID_ARG;

    return ESP_OK;
}

bool key_uri::is_time_based()
{
    return time_based;
}

std::string key_uri::decode_uri(std::string_view _uri)
{
    ESP_LOGD(TAG, "Input uri: %s", _uri.data());
    std::string result;
    char a = '\0', b = '\0';

    size_t idx = 0;
    while(idx < _uri.size()) {
        a = _uri[idx + 1];
        b = _uri[idx + 2];
        if(_uri[idx] == '%' && isxdigit(a) && isxdigit(b)) {
            if (a >= 'a')
                a -= 'a'-'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a'-'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';

            result += (char)(16 * a + b);

            ESP_LOGD(TAG, "a: %c, b: %c, result: %c", _uri[idx + 1], _uri[idx + 2], result[idx]);
            idx += 3;
        } else if(_uri[idx] == '+') {
            result += ' ';
            idx++;
        } else {
            result += _uri[idx];
            idx++;
        }
    }
    return result;
}

std::string key_uri::get_label()
{
    return label;
}

std::string key_uri::get_query_val(std::string_view _query, const std::string& key)
{
    ESP_LOGD(TAG, "Query: %s, key to find: %s", _query.data(), key.c_str());
    auto query_pos = _query.find(key);
    if(query_pos != std::string_view::npos) {
        // _query.substr's position +1 offset is for '='
        auto start_pos = query_pos + key.length() + 1;
        auto end_pos = _query.find_first_of('&', query_pos);
        return std::string(_query.substr(start_pos, end_pos - start_pos)); // Force to make a new string here
    }

    return std::string();
}

std::string key_uri::get_issuer()
{
    return issuer;
}

std::string key_uri::get_secret()
{
    return secret;
}

uint32_t key_uri::get_digits()
{
    return digits;
}

uint32_t key_uri::get_interval()
{
    return interval;
}

uint64_t key_uri::get_counter()
{
    return counter;
}

/**
 * Base32 decoder
 * From https://github.com/google/google-authenticator-libpam/blob/master/src/base32.c
 * @param encoded Encoded text
 * @param result Bytes output
 * @param buf_len Bytes length
 * @return -1 if failed, or length decoded
 */
int key_uri::base32_decode(const char *encoded, uint8_t *result, int buf_len)
{
    if(encoded == nullptr || result == nullptr) return -1;

    // Base32's overhead must be at least 1.4x than the decoded bytes, so the result output must be bigger than this
    if(std::strlen(encoded) > buf_len * 1.4) return -1;

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
int key_uri::base32_encode(const uint8_t *data, int length, char *result, int encode_len)
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

std::string key_uri::get_uri()
{
    return uri;
}


