#include "key_uri_parser.hpp"

#include <utility>
#include <esp_log.h>

#define TAG "uri_parser"

key_uri_parser::key_uri_parser(std::string _uri) : uri(std::move(_uri))
{
}

esp_err_t key_uri_parser::parse()
{
    // Step 1: Probe the schema. If success, move to the 10th char (remove "otpauth://")
    ESP_LOGD(TAG, "Parsing schema...");
    if(uri.find("otpauth://") == std::string_view::npos) return ESP_ERR_INVALID_ARG;
    uri = uri.substr(10);

    // Step 2: Parse type
    ESP_LOGD(TAG, "Parsing type...");
    auto type_str = uri.substr(0, 4);
    if(type_str == "totp") time_based = true;
    else if(type_str == "hotp") time_based = false;
    else return ESP_ERR_INVALID_ARG;
    uri = uri.substr(5); // Skip "[h,t]otp/"

    // Step 3: Parse provider label
    ESP_LOGD(TAG, "Parsing label...");
    auto label_end = uri.find('?');
    if(label_end == std::string_view::npos) return ESP_ERR_INVALID_ARG;
    auto label_raw = uri.substr(0, label_end);
    ESP_LOGD(TAG, "Got label: %s", label_raw.c_str());
    label = decode_uri(label_raw);
    uri = uri.substr(label_end);

    // Step 4: Parse each of the "query parameters"
    // Secret
    ESP_LOGD(TAG, "Parsing secret...");
    secret = get_query_val(uri, "secret");

    // Issuer
    ESP_LOGD(TAG, "Parsing issuer...");
    issuer = decode_uri(get_query_val(uri, "issuer"));

    // Counter (for HOTP only)
    ESP_LOGD(TAG, "Parsing counter...");
    if(!time_based) counter = std::strtol(get_query_val(uri, "counter").data(), nullptr, 10);

    // Interval/Period
    ESP_LOGD(TAG, "Parsing interval...");
    interval = std::strtol(get_query_val(uri, "period").data(), nullptr, 10);
    if(interval < 1) return ESP_ERR_INVALID_ARG;

    // Digits
    ESP_LOGD(TAG, "Parsing digits...");
    digits = std::strtol(get_query_val(uri, "digits").data(), nullptr, 10);
    if(digits < 6) return ESP_ERR_INVALID_ARG;

    return ESP_OK;
}

bool key_uri_parser::is_time_based()
{
    return time_based;
}

std::string key_uri_parser::decode_uri(const std::string& _uri)
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

std::string key_uri_parser::get_label()
{
    return label;
}

std::string key_uri_parser::get_query_val(const std::string& _query, const std::string& key)
{
    ESP_LOGD(TAG, "Query: %s, key to find: %s", _query.data(), key.c_str());
    auto query_pos = _query.find(key);
    if(query_pos != std::string::npos) {
        // _query.substr's position +1 offset is for '='
        auto start_pos = query_pos + key.length() + 1;
        auto end_pos = _query.find_first_of('&', query_pos);
        return _query.substr(start_pos, end_pos - start_pos);
    }

    return std::string();
}

std::string key_uri_parser::get_issuer()
{
    return issuer;
}

std::string key_uri_parser::get_secret()
{
    return secret;
}

uint32_t key_uri_parser::get_digits()
{
    return digits;
}

uint32_t key_uri_parser::get_interval()
{
    return interval;
}

uint64_t key_uri_parser::get_counter()
{
    return counter;
}


