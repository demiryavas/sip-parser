/*
 * CSeqHeader.h
 *
 *  Created on: May 14, 2020
 *      Author: demir
 */
#ifndef _CALL_ID_HEADER_H_
#define _CALL_ID_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipMessage.h"
#include "SipHeader.h"

/*
   The Call-ID header field uniquely identifies a particular invitation
   or all registrations of a particular client.  A single multimedia
   conference can give rise to several calls with different Call-IDs,
   for example, if a user invites a single individual several times to
   the same (long-running) conference.  Call-IDs are case-sensitive and
   are simply compared byte-by-byte.

   Use of cryptographically random identifiers (RFC 1750) in the
   generation of Call-IDs is RECOMMENDED.  Implementations MAY use the
   form "localid@host".

   The compact form of the Call-ID header field is i.

   Example:
      Call-ID: f81d4fae-7dec-11d0-a765-00a0c91e6bf6@biloxi.com
      i:f81d4fae-7dec-11d0-a765-00a0c91e6bf6@192.0.2.4

   Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
   callid   =  word [ "@" word ]

   word        =  1*(alphanum / "-" / "." / "!" / "%" / "*" /
                  "_" / "+" / "`" / "'" / "~" /
                  "(" / ")" / "<" / ">" /
                  ":" / "\" / DQUOTE /
                  "/" / "[" / "]" / "?" /
                  "{" / "}" )
 */
class CallIdHeader : public SipHeader
{
public:
  CallIdHeader()
    : localId({ 0, 0 }), host({ 0, 0 })
  {}

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

  /* Call-ID consists of as localId and host separated with '@' */
  str_pos_t localId;
  str_pos_t host;

};

//---------------------------------------------------------------------------
#endif /* _CALL_ID_HEADER_H_ */
