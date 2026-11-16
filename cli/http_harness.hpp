#pragma once

#include <string>

namespace pm::encryption::cli {

int run_http_server(const std::string& host, int port, bool once);
int run_http_client(const std::string& base_url, const std::string& prompt, bool tamper);

} // namespace pm::encryption::cli
