/*
 * AcceptHeader.h
 *
 *  Created on: Sep 2, 2021
 *      Author: demir
 */
#ifndef _ALLOW_HEADER_H_
#define _ALLOW_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipHeader.h"
#include "SipMessage.h"

// The Allow header field lists the set of methods supported by the UA generating the message.
//
// All methods, including ACK and CANCEL, understood by the UA MUST be included in the list of methods 
// in the Allow header field, when present. The absence of an Allow header field MUST NOT be interpreted 
// to mean that the UA sending the message supports no methods. Rather, it implies that the UA is not 
// providing any information on what methods it supports.
//
// Supplying an Allow header field in responses to methods other than OPTIONS reduces the number of messages needed.
//
// Example:
//
//   Allow: INVITE, ACK, OPTIONS, CANCEL, BYE
// 
// Allow  =  "Allow" HCOLON [Method *(COMMA Method)]

#define MAX_NUM_ALLOW_METHODS 14
typedef std::array<str_pos_t, MAX_NUM_ALLOW_METHODS> allow_method_array_t;
typedef std::array<enum sip_method, MAX_NUM_ALLOW_METHODS> allow_method_enum_array_t;

class AllowHeader : public SipHeader
{
public:
  AllowHeader()
    : num_allow_methods(0), allow_methods(), allow_method_enums()
  { }

  virtual ~AllowHeader() {}

  /* Parsing utility. Consider the value part of header starts from 'pos' with length 'buflen'.
     On return, 'parsing_stat' attribute of class instance reflects parsing status.
     Function returns the current position which may indicate the position of
     problem in case of failure
  */
  const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen);

  /* both provide the value part, which can be re-formatted if the header has
     subparts or represents a multiple-header */
  std::string GetHeaderValue();
  int GetHeaderValue(std::string& value);

  /* provides the pointer to value part of the header in question.
     No any additional copy applied. */
  int GetHeaderValue(RawData& value);

  void PrintOut(std::ostringstream& buf);

  uint32_t  num_allow_methods;
  allow_method_array_t allow_methods;
  allow_method_enum_array_t allow_method_enums;
};
//---------------------------------------------------------------------------
#endif // _ALLOW_HEADER_H_

