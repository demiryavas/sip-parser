/*
 * FromHeader.h
 *
 *  Created on: May 23, 2020
 *      Author: demir
 */

#ifndef _FROM_HEADER_H_
#define _FROM_HEADER_H_
 //---------------------------------------------------------------------------
#include "SipMessage.h"
#include "SipHeader.h"
#include "SipUri.h"

/* 
   The From header field indicates the initiator of the request.  This
   may be different from the initiator of the dialog.  Requests sent by
   the callee to the caller use the callee's address in the From header
   field.

   The optional "display-name" is meant to be rendered by a human user
   interface.  A system SHOULD use the display name "Anonymous" if the
   identity of the client is to remain hidden.  Even if the "display-
   name" is empty, the "name-addr" form MUST be used if the "addr-spec"
   contains a comma, question mark, or semicolon.

   When the header field value contains a display name, the URI
   including all URI parameters is enclosed in "<" and ">".  If no "<"
   and ">" are present, all parameters after the URI are header
   parameters, not URI parameters.  The display name can be tokens, or a
   quoted string, if a larger character set is desired.

   Even if the "display-name" is empty, the "name-addr" form MUST be
   used if the "addr-spec" contains a comma, semicolon, or question
   mark.  There may or may not be LWS between the display-name and the
   "<".

   The compact form of the From header field is f.

   Examples:
      From: "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
      From: sip:+12125551212@server.phone2net.com;tag=887s
      f: Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8

   From           =  ( "From" / "f" ) HCOLON from-spec
   from-spec      =  ( name-addr / addr-spec ) *( SEMI from-param )
   name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
   addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
   display-name   =  *(token LWS)/ quoted-string
   from-param     =  tag-param / generic-param
   tag-param      =  "tag" EQUAL token

   quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE
   qdtext         =  LWS / %x21 / %x23-5B / %x5D-7E / UTF8-NONASCII
                     ; Starting from '!' as excluding '"' and '\'
   The backslash character ("\") MAY be used as a single-character
   quoting mechanism only within quoted-string and comment constructs.
   Unlike HTTP/1.1, the characters CR and LF cannot be escaped by this
   mechanism to avoid conflict with line folding and header separation.

   quoted-pair    =  "\" (%x00-09 / %x0B-0C / %x0E-7F)
                     ; excluding LF and CR
 */

class FromHeader : public SipHeader
{
public:
  FromHeader()
    : displayName({ 0, 0 }), url_str({ 0, 0 }), url(NULL), tag({ 0, 0 }), num_params(0), params(), addrType(ADDR_NONE), hdrName("From")
  {}

  virtual ~FromHeader() {
    if (url) {
      delete url;
      url = NULL;
    }
  }

  /* Parsing utility */
  const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen);

  /* parses URI part of From header if main parsing is done. */
  int ParseUrlPart();

  /* both provide the value part, which can be re-formatted if the header has
     subparts or represents a multiple-header */
  std::string GetHeaderValue();
  int GetHeaderValue(std::string& value);

  /* provides the pointer to value part of the header in question.
     No any additional copy applied. */
  int GetHeaderValue(RawData& value);

  void PrintOut(std::ostringstream& buf);

  str_pos_t displayName;
  str_pos_t url_str;
  SipUri* url;
  str_pos_t tag;           /**< tag parameter for quick access */
  uint32_t  num_params;
  SipParamArray_t params;  /**< From parameters */

protected:
  AddressType_t addrType;

  const char* hdrName; /* this class' implementation can be shared with 'To' header implementation */
};
//---------------------------------------------------------------------------
#endif /* _FROM_HEADER_H_ */