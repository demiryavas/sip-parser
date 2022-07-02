
/*
 * AcceptHeader.h
 *
 *  Created on: Sep 1, 2021
 *      Author: demir
 */
#ifndef _ACCEPT_ENCODING_HEADER_H_
#define _ACCEPT_ENCODING_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipHeader.h"
#include "SipMessage.h"

// The Accept-Encoding header field is similar to Accept, but restricts the content-codings [HTTP RFC 2616 Sec.3.5] 
// that are acceptable in the response. An empty Accept-Encoding header field is permissible.  It is equivalent to 
// Accept-Encoding: identity, that is, only the identity encoding, meaning no encoding, is permissible.
// If no Accept-Encoding header field is present, the server SHOULD assume a default value of identity.
// This differs slightly from the HTTP definition, which indicates that when not present, any encoding can be used, 
// but the identity encoding is preferred.
// Example:
//    Accept-Encoding: gzip
//    Accept-Encoding: compress, gzip
//    Accept-Encoding:
//    Accept-Encoding: *
//    Accept-Encoding: compress;q=0.5, gzip;q=1.0
//    Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0
//
// Accept-Encoding  =  "Accept-Encoding" HCOLON
//                      [ encoding *(COMMA encoding) ]
// encoding         =  codings *(SEMI accept-param)
// codings          =  content-coding / "*"
// content-coding   =  token
// accept-param     =  ("q" EQUAL qvalue) / generic-param
// qvalue           =  ( "0" [ "." 0*3DIGIT ] )
//                     / ( "1" [ "." 0*3("0") ] )
// generic-param    =  token [ EQUAL gen-value ]
// gen-value        =  token / host / quoted-string

typedef struct accept_encoding_t
{
  str_pos_t coding;
  SipParamArray_t params;  /**< Accept-Encoding parameters */
  uint32_t  num_params;
} accept_encoding_t;

#define MAX_NUM_ACCEPT_ENCODINGS 8
typedef std::array<accept_encoding_t, MAX_NUM_ACCEPT_ENCODINGS> accept_encoding_array_t;

class AcceptEncodingHeader : public SipHeader
{
public:
  AcceptEncodingHeader()
    : num_accept_encodings(0), accept_encodings()
  { }

  virtual ~AcceptEncodingHeader() {}

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

  uint32_t  num_accept_encodings;
  accept_encoding_array_t accept_encodings;
};
//---------------------------------------------------------------------------
#endif // _ACCEPT_ENCODING_HEADER_H_
