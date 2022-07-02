/*
 * ContentTypeHeader.h
 *
 *  Created on: June 24, 2020
 *      Author: demir
 */
#ifndef _CONTENT_TYPE_HEADER_H_
#define _CONTENT_TYPE_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipHeader.h"
#include "SipMessage.h"

/*
  The Content-Type header field indicates the media type of the
  message-body sent to the recipient.  The "media-type" element is
  defined in [H3.7].  The Content-Type header field MUST be present if
  the body is not empty.  If the body is empty, and a Content-Type
  header field is present, it indicates that the body of the specific
  type has zero length (for example, an empty audio file).

  The compact form of the header field is c.

  Examples:
      Content-Type: application/sdp
      c: text/html; charset=ISO-8859-4
      Content-Type: multipart/signed;
        protocol="application/pkcs7-signature";
        micalg=sha1; boundary=boundary42

  Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
  media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
  m-type           =  discrete-type / composite-type
  discrete-type    =  "text" / "image" / "audio" / "video"
                      / "application" / extension-token
  composite-type   =  "message" / "multipart" / extension-token
  extension-token  =  ietf-token / x-token
  ietf-token       =  token
  x-token          =  "x-" token
  m-subtype        =  extension-token / iana-token
  iana-token       =  token
  m-parameter      =  m-attribute EQUAL m-value
  m-attribute      =  token
  m-value          =  token / quoted-string
 */
class ContentTypeHeader : public SipHeader
{
public:
  ContentTypeHeader()
    : m_type({0, 0}), m_subtype({ 0, 0 }), params(), num_params(0)
  {}

  /* Parsing utility. Consider the value part of header starts from 'pos' with length 'varlen' */
  const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen);

  /* TODO: The following 3 functions are defined to provide formatted header value,
           which are using different approaches. We need eliminate some of them by
           selecting appropriate one(s). */
  /* both provide the value part, which can be re-formatted if the header has
     subparts or represents a multiple-header */
  std::string GetHeaderValue();
  int GetHeaderValue(std::string& value);

  /* provides the pointer to value part of the header in question.
     No any additional copy applied. */
  int GetHeaderValue(RawData& value);

  /* Prints the content of header into 'buf' for debug purposes */
  void PrintOut(std::ostringstream& buf);

  str_pos_t m_type;
  str_pos_t m_subtype;
  SipParamArray_t params;  /**< Content-Type parameters */
  uint32_t  num_params;

};

//---------------------------------------------------------------------------
#endif // _CONTENT_TYPE_HEADER_H_
