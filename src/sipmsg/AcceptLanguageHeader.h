/*
 * AcceptHeader.h
 *
 *  Created on: Sep 2, 2021
 *      Author: demir
 */
#ifndef _ACCEPT_LANGUAGE_HEADER_H_
#define _ACCEPT_LANGUAGE_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipHeader.h"
#include "SipMessage.h"

// The Accept-Language header field is used in requests to indicate the preferred languages 
// for reason phrases, session descriptions, or status responses carried as message bodies 
// in the response.  If no Accept-Language header field is present, the server SHOULD assume 
// all languages are acceptable to the client.
// The Accept - Language header field follows the syntax defined in[H14.4].The rules for 
// ordering the languages based on the "q" parameter apply to SIP as well.

// Example:
//    Accept-Language: da, en-gb;q=0.8, en;q=0.7
//
// Accept-Language  =  "Accept-Language" HCOLON
//                      [language * (COMMA language)]
// language         =  language-range *(SEMI accept-param)
// language-range   =  ((1*8ALPHA *("-" 1*8ALPHA)) / "*")

typedef struct accept_language_t
{
  str_pos_t language_range;
  SipParamArray_t params;  /**< Accept-Language parameters */
  uint32_t  num_params;
} accept_language_t;

#define MAX_NUM_ACCEPT_LANGUAGE 8
typedef std::array<accept_language_t, MAX_NUM_ACCEPT_LANGUAGE> accept_language_array_t;

class AcceptLanguageHeader : public SipHeader
{
public:
  AcceptLanguageHeader()
    : num_accept_languages(0), accept_languages()
  { }

  virtual ~AcceptLanguageHeader() {}

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

  uint32_t  num_accept_languages;
  accept_language_array_t accept_languages;
};
//---------------------------------------------------------------------------
#endif // _ACCEPT_LANGUAGE_HEADER_H_

