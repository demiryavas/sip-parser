/*
 * SubjectHeader.h
 *
 *  Created on: June 24, 2020
 *      Author: demir
 */

#ifndef _SUBJECT_HEADER_H_
#define _SUBJECT_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipMessage.h"
#include "SipHeader.h"

/*
   The Subject header field provides a summary or indicates the nature
   of the call, allowing call filtering without having to parse the
   session description.  The session description does not have to use
   the same subject indication as the invitation.

   The compact form of the Subject header field is s.

   Example:

      Subject: Need more boxes
      s: Tech Support

   Subject  =  ( "Subject" / "s" ) HCOLON [TEXT-UTF8-TRIM]

   The TEXT-UTF8 rule is only used for descriptive field contents and
   values that are not intended to be interpreted by the message parser.
   Words of *TEXT-UTF8 contain characters from the UTF-8 charset (RFC
   2279).  The TEXT-UTF8-TRIM rule is used for descriptive field
   contents that are n t quoted strings, where leading and trailing LWS
   is not meaningful.  In this regard, SIP differs from HTTP, which uses
   the ISO 8859-1 character set.

      TEXT-UTF8-TRIM  =  1*TEXT-UTF8char *(*LWS TEXT-UTF8char)
      TEXT-UTF8char   =  %x21-7E / UTF8-NONASCII
      UTF8-NONASCII   =  %xC0-DF 1UTF8-CONT
                      /  %xE0-EF 2UTF8-CONT
                      /  %xF0-F7 3UTF8-CONT
                      /  %xF8-Fb 4UTF8-CONT
                      /  %xFC-FD 5UTF8-CONT
      UTF8-CONT       =  %x80-BF

   A CRLF is allowed in the definition of TEXT-UTF8-TRIM only as part of
   a header field continuation.  It is expected that the folding LWS
   will be replaced with a single SP before interpretation of the TEXT-
   UTF8-TRIM value.
 */

/* The following array is defined to hadle folded SUbject header parts. 
   Each part consists of a folded part such that rebuilding of the header content, 
   a single space character will be included in the output string */
#define MAX_NUM_SUBJ_PARTS 8
typedef std::array<str_pos_t, MAX_NUM_SUBJ_PARTS> subj_fold_parts_array_t;

class SubjectHeader : public SipHeader
{
public:
  SubjectHeader()
    : subject({ 0, 0 }), num_fold_parts(0), fold_parts()
  {}

  /* Parsing utility */
  const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen);

  /* both provide the value part, which can be re-formatted if the header has
     subparts or represents a multiple-header */
  std::string GetHeaderValue();
  int GetHeaderValue(std::string& value);

  /* provides the pointer to value part of the header in question.
     No any additional copy applied. */
  int GetHeaderValue(RawData& value);

  void PrintOut(std::ostringstream& buf);

  /* to indicate all text including LWS chars (SP, TAB, CRLF) (except frontmost LWS chars)
     in a struct */
  str_pos_t subject;

  /* folded parts */
  uint32_t num_fold_parts;
  subj_fold_parts_array_t fold_parts;

};


//---------------------------------------------------------------------------
#endif /* _SUBJECT_HEADER_H_ */
