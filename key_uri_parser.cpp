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
    ESP_LOGI(TAG, "Parsing schema...");
    if(uri.find("otpauth://") == std::string_view::npos) return ESP_ERR_INVALID_ARG;
    uri = uri.substr(10);

    // Step 2: Parse type
    ESP_LOGI(TAG, "Parsing type...");
    auto type_str = uri.substr(0, 4);
    if(type_str == "totp") time_based = true;
    else if(type_str == "hotp") time_based = false;
    else return ESP_ERR_INVALID_ARG;
    uri = uri.substr(5); // Skip "[h,t]otp/"

    // Step 3: Parse provider label
    ESP_LOGI(TAG, "Parsing label...");
    auto label_end = uri.find('?');
    if(label_end == std::string_view::npos) return ESP_ERR_INVALID_ARG;
    label = decode_uri(uri.substr(0, label_end));
    uri = uri.substr(label_end);

    // Step 4: Parse each of the "query parameters"
    // Secret
    ESP_LOGI(TAG, "Parsing secret...");
    secret = get_query_val(uri, "secret");

    // Issuer
    ESP_LOGI(TAG, "Parsing issuer...");
    issuer = decode_uri(get_query_val(uri, "issuer"));

    // Counter (for HOTP only)
    ESP_LOGI(TAG, "Parsing counter...");
    if(!time_based) counter = std::strtol(get_query_val(uri, "counter").data(), nullptr, 10);

    // Interval/Period
    ESP_LOGI(TAG, "Parsing interval...");
    interval = std::strtol(get_query_val(uri, "period").data(), nullptr, 10);
    if(interval < 1) return ESP_ERR_INVALID_ARG;

    // Digits
    ESP_LOGI(TAG, "Parsing digits...");
    digits = std::strtol(get_query_val(uri, "digits").data(), nullptr, 10);
    if(digits < 6) return ESP_ERR_INVALID_ARG;

    return ESP_OK;
}

bool key_uri_parser::is_time_based()
{
    return time_based;
}

std::string key_uri_parser::decode_uri(std::string_view _uri)
{
    std::string result;
    result.reserve(_uri.size());
    char a = '\0', b = '\0';
    for(auto idx = 0; idx < (int)(_uri.size() - 2); idx++) {
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

            result[idx] = 16 * a + b;
        } else if(_uri[idx] == '+') {
            result[idx] = ' ';
        } else {
            result[idx] = _uri[idx];
        }
    }
    return result;
}

std::string key_uri_parser::get_label()
{
    return label;
}

std::string_view key_uri_parser::get_query_val(std::string_view _query, const std::string& key)
{
    auto query_pos = _query.find(key);
    if(query_pos != std::string_view::npos) {
        // _query.substr's position +1 offset is for '='
        return _query.substr(query_pos + key.length() + 1, _query.find_first_of('&', query_pos));
    }

    return std::string_view();
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


