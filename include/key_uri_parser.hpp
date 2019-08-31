#pragma once

#include <string>
#include <string_view>
#include <esp_err.h>

class key_uri_parser
{
    public:
        explicit key_uri_parser(const std::string& _uri);
        esp_err_t parse();
        bool is_time_based();
        std::string get_label();
    private:
        bool time_based;
        static std::string decode_uri(std::string_view _uri);
        static std::string_view get_query_val(std::string_view _query, const std::string& key);
        std::string_view uri;
        std::string secret;
        std::string label;
        std::string issuer;
        uint64_t counter = 0;
        uint32_t interval = 0;
        uint32_t digits = 0;
};
