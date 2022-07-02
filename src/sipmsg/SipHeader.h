
/*
 * SipHeader.h
 *
 *  Created on: June 1, 2020
 *      Author: demir
 */
#ifndef _SIP_HEADER_H_
#define _SIP_HEADER_H_
 //---------------------------------------------------------------------------
#include "RawData.h"

#include <sstream>      // std::ostringstream

#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_DIGIT(c)         ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_DIGIT(c))
#define IS_HEX(c)           (IS_DIGIT(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_WORD(c)          (IS_ALPHANUM(c) || (c) == '-' || (c) == '.' || (c) == '!' || \
   (c) == '%' || (c) == '*' || (c) == '_' || (c) == '+' || (c) == '`' || (c) == '\'' || \
   (c) == '~' || (c) == '(' || (c) == ')' || (c) == '<' || (c) == '>' || (c) == ':' ||  \
   (c) == '\\' || (c) == '"' || (c) == '/' || (c) == '[' || (c) == ']' || (c) == '?' || \
   (c) == '{'  || (c) == '}')
#define IS_TOKEN(c)         (IS_ALPHANUM(c) || (c) == '-' || (c) == '.' || \
   (c) == '!' || (c) == '%' || (c) == '*' || (c) == '_' || (c) == '+' || \
   (c) == '`' || (c) == '\'' || (c) == '~')
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
   (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
   (c) == ')')
#define IS_UNRESERVED(c)    (IS_ALPHANUM(c) || IS_MARK(c))
#define IS_ESCAPED_CHAR(c)  ((c) == '%')
#define IS_LWS(c)           ((c) == ' ' || (c) == '\t' || (c) == CR || (c) == LF)

#define IS_WSP(c)           ((c) == ' ' || (c) == '\t')

#define IS_HOST_CHAR(c)     (IS_ALPHANUM(c) || (c) == '.' || (c) == '-')

/* paramchar         =  param-unreserved / unreserved / escaped
   param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
 */
#define IS_PARAM_UNRESERVED(c) ((c) == '[' || (c) == ']' || (c) == '/' || \
  (c) == ':' || (c) == '&' || (c) == '+' || (c) == '$' )
#define IS_PARAM_CHAR(c)    (IS_PARAM_UNRESERVED(c) || IS_UNRESERVED(c) || \
  IS_ESCAPED_CHAR(c))

typedef enum
{
  ADDR_NONE,
  NAME_ADDR,
  ADDR_SPEC
} AddressType_t;

typedef enum
{
  NOT_PARSED_YET,
  PARSED_SUCCESSFULLY,
  PARSING_FAILED_NO_DATA,
  PARSING_FAILED_STATE_DEAD,
  PARSING_FAILED_STATE_UNHANDLED,
  PARSING_FAILED_MAX_RANGE,
  PARSING_FAILED_INVALID_METHOD,
  PARSING_FAILED_UNEXPECTED_CHAR,
  PARSING_FAILED_UNCLEAR_REASON
} ParsingStatus_t;

/* Provides an interface definition for SIP header implementations */
class SipHeader
{
public:
  SipHeader()
    : parsing_stat(NOT_PARSED_YET), rawdata()
  {}

  /* Parsing utility. Consider the value part of header starts from 'pos' with length 'buflen'.
     On return, 'parsing_stat' attribute of class instance reflects parsing status.
     Function returns the current position which may indicate the position of
     problem in case of failure 
  */
  virtual const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen) = 0;

  /* TODO: The following 3 functions are defined to provide formatted header value,
           which are using different approaches. We need eliminate some of them by
           selecting appropriate one(s). */
  /* both provide the value part, which can be re-formatted if the header has
     subparts or represents a multiple-header */
  virtual std::string GetHeaderValue() = 0;
  virtual int GetHeaderValue(std::string& value) = 0;

  /* provides the pointer to value part of the header in question.
     No any additional copy applied. */
  virtual int GetHeaderValue(RawData& value) = 0;

  /* Prints the content of header into 'buf' for debug purposes */
  virtual void PrintOut(std::ostringstream& buf) = 0;

  // TODO make pure virtual
  virtual bool operator==(const SipHeader& other) { return false; };
  virtual bool operator!=(const SipHeader& other) { return !(operator==(other)); };

  inline static const char* GetParsingStatInText(ParsingStatus_t ps)
  {
    switch (ps)
    {
      case NOT_PARSED_YET:                 return "NOT_PARSED_YET";
      case PARSED_SUCCESSFULLY:            return "PARSED_SUCCESSFULLY";
      case PARSING_FAILED_NO_DATA:         return "PARSING_FAILED_NO_DATA";
      case PARSING_FAILED_STATE_DEAD:      return "PARSING_FAILED_STATE_DEAD";
      case PARSING_FAILED_STATE_UNHANDLED: return "PARSING_FAILED_STATE_UNHANDLED";
      case PARSING_FAILED_MAX_RANGE:       return "PARSING_FAILED_MAX_RANGE";
      case PARSING_FAILED_INVALID_METHOD:  return "PARSING_FAILED_INVALID_METHOD";
      case PARSING_FAILED_UNEXPECTED_CHAR: return "PARSING_FAILED_UNEXPECTED_CHAR";
      case PARSING_FAILED_UNCLEAR_REASON:  return "PARSING_FAILED_UNCLEAR_REASON";
      default:                             return "Unknown_Parsing_Status";
    }
  }

  ParsingStatus_t parsing_stat;

protected:
  /* raw-data points the header position in message bytes. Actually, header class
     is not owner the raw-data, so should not clear it on destruction */
  RawData rawdata;
};

//---------------------------------------------------------------------------
#endif // _SIP_HEADER_H_