/*
 * AcceptHeader.h
 *
 *  Created on: Aug 26, 2021
 *      Author: demir
 */
#ifndef _ACCEPT_HEADER_H_
#define _ACCEPT_HEADER_H_
//---------------------------------------------------------------------------
#include "SipHeader.h"
#include "SipMessage.h"

// The Accept header field follows the syntax defined in[HTTP RFC 2616 Sec.14.1].
// The semantics are also identical, with the exception that if no Accept
// header field is present, the server SHOULD assume a default value of
// application/sdp.
//
// An empty Accept header field means that no formats are acceptable.
// 
// Example:
//    Accept: application/sdp;level=1, application/x-private, text/html
// 
// 
// Accept         =  "Accept" HCOLON
//                     [ accept-range *(COMMA accept-range) ]
// accept-range   =  media-range *(SEMI accept-param)
// media-range    =  ( "*/*"                                   
//                   / ( m-type SLASH "*" )
//                   / ( m-type SLASH m-subtype )
//                   ) *( SEMI m-parameter )
// accept-param   =  ("q" EQUAL qvalue) / generic-param
// qvalue         =  ( "0" [ "." 0*3DIGIT ] )
//                   / ( "1" [ "." 0*3("0") ] )
// generic-param  =  token [ EQUAL gen-value ]
// gen-value      =  token / host / quoted-string
 
typedef struct accept_range_t
{
  str_pos_t m_type;
  str_pos_t m_subtype;
  SipParamArray_t params;  /**< Accept parameters */
  uint32_t  num_params;
} accept_range_t;

#define MAX_NUM_ACCEPT_RANGES 16
typedef std::array<accept_range_t, MAX_NUM_ACCEPT_RANGES> accept_range_array_t;

class AcceptHeader : public SipHeader
{
public:
  AcceptHeader()
    : num_accept_ranges(0), accept_ranges()
  { }

  virtual ~AcceptHeader() {}

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

  uint32_t  num_accept_ranges;
  accept_range_array_t accept_ranges;
};
//---------------------------------------------------------------------------
#endif // _ACCEPT_HEADER_H_
