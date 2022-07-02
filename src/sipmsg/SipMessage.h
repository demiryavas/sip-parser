/*
 * SipMessage.h
 *
 *  Created on: Apr 12, 2020
 *      Author: demir
 */

#ifndef SIPMESSAGE_H_
#define SIPMESSAGE_H_
//-----------------------------------------------------------------------------
#include "RawData.h"
#include "sipparser.h"

// integer types
#ifdef WIN32
  #include <stdint.h>
#else
  #include <inttypes.h>
  #include <sys/time.h>
#endif

#include <string>
#include <list>
#include <vector>
#include <array>

enum sip_element_status_t{ NONE = 0, FIELD, VALUE };

typedef struct str_pos
{
  uint32_t start;
  uint32_t length;
} str_pos_t;

typedef struct header_pos
{
  str_pos_t fieldpos;
  str_pos_t valuepos;
} header_pos_t;

typedef std::list<header_pos_t*> SipHeaderPosList_t;
#define MAX_NUM_HEADERS 256
typedef std::array<header_pos_t, MAX_NUM_HEADERS> SipHeadersArray_t;
#define MIN_NUM_HEADERS 32
typedef std::array<header_pos_t, MIN_NUM_HEADERS> SipHeadersMinArray_t;

typedef struct param_pos
{
  str_pos_t type;
  str_pos_t value;
} param_pos_t;


typedef std::list<param_pos_t*> SipParamPosList_t;
#define MAX_NUM_PARAMS 32
typedef std::array<param_pos_t, MAX_NUM_PARAMS> SipParamArray_t;

class SipMessage
{
public:
  SipMessage()
    : builder(0), parser(0), type(SIP_BOTH), method(SIP_ACK), status_code(0),
      response_status({0, 0}), request_path({0, 0}), request_url({0, 0}), msg_body({0, 0}),
      num_headers(0), last_header_element(NONE), headers(), should_keep_alive(0),
      sip_major(0), sip_minor(0), bias(0), message_begin_cb_called(0), message_begin_pos(0),
      headers_complete_cb_called(0), headers_complete_pos(0), message_complete_cb_called(0),
      message_complete_pos(0), status_cb_called(0), message_complete_on_eof(0), body_is_final(0)
  {}

  /* Returns a string version of the SIP method. */
  static const char* GetMethodStr(enum sip_method m) { return sip_method_str(m); }
  static const char* GetLongHeaderName(char shName);
  static const char GetShortHeaderName(const char* hdrName);

  /* Utility function */
  static void PrintoutData(std::ostringstream& buff, unsigned char* data, unsigned int len);

  int GetRequestUrl(RawData& value);

  /* returns number of headers indicated with "headerName" in the message */
  int GetHeaderCount(unsigned char* headerName);
  /* in the case of header name has no terminating character */
  int GetHeaderCount(unsigned char* headerName, uint32_t hnmlen);

  /* returns the value part of the 'idx'th occurrence of the header "headerName" */
  std::string GetHeaderValue(unsigned char* headerName, uint32_t idx=0);
  std::string GetHeaderValue(unsigned char* headerName, uint32_t hnmlen, uint32_t idx=0);

  int GetHeaderValue(unsigned char* headerName, std::string& value, uint32_t idx=0);
  int GetHeaderValue(unsigned char* headerName, uint32_t hnmlen, std::string& value, uint32_t idx=0);

  /* provides the pointer to value part of the header in question. No any additional copy applied. */
  int GetHeaderValue(unsigned char* headerName, RawData& value, uint32_t idx=0);
  int GetHeaderValue(unsigned char* headerName, uint32_t hnmlen, RawData& value, uint32_t idx=0);

  /* Followings provide data from multiple headers in the message in a list.
     Does not distiguish multiple headers received in a header as seperated with comma (,) */
  int GetHeaderValuesInList(unsigned char* headerName, std::list<std::string>& strlist);
  int GetHeaderValuesInList(unsigned char* headerName, uint32_t hnmlen, std::list<std::string>& strlist);

  int GetHeaderValuesInList(unsigned char* headerName, std::list<RawData>& rwdlist);
  int GetHeaderValuesInList(unsigned char* headerName, uint32_t hnmlen, std::list<RawData>& rwdlist);

  size_t GetBodySize() { return msg_body.length; }
  RawData* GetBody();
  int GetBody(RawData& rawData);

  void PrintOut(std::ostringstream &buf); // { /* to be implemented */ }

  /* In the case of builder, we considered that all data will be
     deallocated. Otherwise all data point into raw data. */
  int builder;

  std::vector<char> v1;
  int parser; /* '>0' indicates HttpMessage is from parsing otherwise for building */

  enum sip_parser_type type;
  enum sip_method method;
  int status_code;
  str_pos_t response_status; 
  str_pos_t request_path;
  str_pos_t request_url;

  str_pos_t msg_body;
  uint32_t num_headers;
  sip_element_status_t last_header_element;
  SipHeadersArray_t  headers;
  int should_keep_alive;

  unsigned short sip_major;
  unsigned short sip_minor;

  int bias;

  int message_begin_cb_called;
  unsigned int message_begin_pos;
  int headers_complete_cb_called;
  unsigned int headers_complete_pos;
  int message_complete_cb_called;
  unsigned int message_complete_pos;
  int status_cb_called; /* new with 2.9.0 */
  int message_complete_on_eof;
  int body_is_final;
};
//-----------------------------------------------------------------------------
#endif /* SIPMESSAGE_H_ */
