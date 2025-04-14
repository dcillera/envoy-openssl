#include <string>
#include <cctype>

#include "http_filter.h"

#include "envoy/server/filter_config.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Http {

HttpSampleDecoderFilterConfig::HttpSampleDecoderFilterConfig(
    const sample::Decoder& proto_config)
    : key_(proto_config.key()), val_(proto_config.val()) {}

HttpSampleDecoderFilter::HttpSampleDecoderFilter(HttpSampleDecoderFilterConfigSharedPtr config)
    : config_(config) {}

HttpSampleDecoderFilter::~HttpSampleDecoderFilter() {}

void HttpSampleDecoderFilter::onDestroy() {}

const LowerCaseString HttpSampleDecoderFilter::headerKey() const {
  return LowerCaseString(config_->key());
}

const std::string HttpSampleDecoderFilter::headerValue() const {
  return config_->val();
}

FilterHeadersStatus HttpSampleDecoderFilter::decodeHeaders(RequestHeaderMap& headers, bool) {
  // add a header
  headers.addCopy(headerKey(), headerValue());
  auto path = headers.getPathValue(); // Http::LowerCaseString(":path")
  auto xffData = headers.getForwardedForValue();
  // if (xffData == nullptr) {
  //   return FilterHeadersStatus::Continue;
  // }
    
  std::cout << "Path: " << path << std::endl;
  std::cout << "XFF: " << xffData << std::endl;

  // Remove blank chars
  std::string cleanXff(xffData);
  cleanXff.erase(std::remove_if(cleanXff.begin(), cleanXff.end(), ::isspace),
                                cleanXff.end());
  std::cout << "xffData cleaned: " << cleanXff << std::endl;
 
  // Parse and check XFF IP addresses
  std::istringstream istr(cleanXff);
  for (std::string ipString; std::getline(istr, ipString, ','); ) {
    std::cout << "ipString: " << ipString << std::endl;
    auto ip=Network::Utility::parseInternetAddressNoThrow(ipString);
    if(ip == nullptr) {
       // Incorrect data (possibly malicious)
      std::cout << "XFF IP: WRONG" << std::endl;
     
      decoder_callbacks_->sendLocalReply(Envoy::Http::Code::BadRequest, "Bad IP in XFF Header", nullptr, absl::nullopt, "Bad_IP_in_XFF_header");

      return FilterHeadersStatus::StopIteration;
   }
   else {
     std::cout << "XFF IP: " << ip->asString() << std::endl;
   }
  } 

  return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpSampleDecoderFilter::decodeData(Buffer::Instance&, bool) {
  return FilterDataStatus::Continue;
}

void HttpSampleDecoderFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

} // namespace Http
} // namespace Envoy
