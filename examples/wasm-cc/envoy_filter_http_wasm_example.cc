// NOLINT(namespace-envoy)
#include <arpa/inet.h>
#include <iostream>
#include <sstream>  
#include <string>
#include <string_view>
#include <unordered_map>

#include "proxy_wasm_intrinsics.h"


class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}

  bool onStart(size_t) override;
  bool onConfigure(size_t) override;
  void onTick() override;
};

class ExampleContext : public Context {
public:
  explicit ExampleContext(uint32_t id, RootContext* root) : Context(id, root) {}

  void onCreate() override;
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override;
  void onDone() override;
  void onLog() override;
  void onDelete() override;
};
static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(ExampleContext),
                                                      ROOT_FACTORY(ExampleRootContext),
                                                      "my_root_id");

bool ExampleRootContext::onStart(size_t) {
  LOG_TRACE("onStart");
  return true;
}

bool ExampleRootContext::onConfigure(size_t) {
  LOG_TRACE("onConfigure");
  proxy_set_tick_period_milliseconds(1000); // 1 sec
  return true;
}

void ExampleRootContext::onTick() { LOG_TRACE("onTick"); }

void ExampleContext::onCreate() { LOG_WARN(std::string("onCreate " + std::to_string(id()))); }

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto xffData = getRequestHeader("x-forwarded-for")->toString();
  LOG_INFO(std::string("x-forwarded-for: ") + xffData);
 
   // Remove blank/tab/newline chars
  xffData.erase(std::remove_if(xffData.begin(), xffData.end(), ::isspace),
                               xffData.end());
  std::cout << "xffData cleaned: " << xffData << std::endl;
 
    // Parse and check XFF comma separated IP addresses
  std::istringstream istr (xffData);
  for (std::string ipString; std::getline(istr, ipString, ','); ) {
    std::cout << "ipString: " << ipString << std::endl;
    unsigned char buf[sizeof(struct in6_addr)];
    int s = inet_pton(AF_INET, ipString.c_str(), buf);
    if( s <= 0) {
        // Not a valid IPV4, try IPV6
      s = inet_pton(AF_INET6, ipString.c_str(), buf);
      if(s <= 0)
      {
          // No valid IP address at all
        std::cout << "XFF IP: BAD" << std::endl;

         // Send a local reply
        CHECK_RESULT(sendLocalResponse(400, "Bad XFF IP address", "Bad XFF IP address", {}));

        return FilterHeadersStatus::StopIteration;
      }
   }
  }
  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus ExampleContext::onResponseHeaders(uint32_t, bool) {
  return FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length,
                                               bool /* end_of_stream */) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  LOG_ERROR(std::string("onRequestBody ") + std::string(body->view()));
  return FilterDataStatus::Continue;
}

FilterDataStatus ExampleContext::onResponseBody(size_t body_buffer_length,
                                                bool /* end_of_stream */) {
  return FilterDataStatus::Continue;
}

void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }
