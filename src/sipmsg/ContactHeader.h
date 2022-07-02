/*
 * ContentTypeHeader.h
 *
 *  Created on: August 09, 2021
 *      Author: demir
 */
#ifndef _CONTACT_HEADER_H_
#define _CONTACT_HEADER_H_
//---------------------------------------------------------------------------
#include "SipHeader.h"
#include "SipMessage.h"
#include "SipUri.h"

/*
   The Contact header field provides a SIP or SIPS URI that can be used
   to contact that specific instance of the UA for subsequent requests.
   The Contact header field MUST be present and contain exactly one SIP
   or SIPS URI in any request that can result in the establishment of a
   dialog.  For the methods defined in this specification, that includes
   only the INVITE request.  For these requests, the scope of the
   Contact is global.  That is, the Contact header field value contains
   the URI at which the UA would like to receive requests, and this URI
   MUST be valid even if used in subsequent requests outside of any
   dialogs.

   If the Request-URI or top Route header field value contains a SIPS
   URI, the Contact header field MUST contain a SIPS URI as well.

A Contact header field value provides a URI whose meaning depends on
   the type of request or response it is in.

   A Contact header field value can contain a display name, a URI with
   URI parameters, and header parameters.

   This document defines the Contact parameters "q" and "expires".
   These parameters are only used when the Contact is present in a
   REGISTER request or response, or in a 3xx response.  Additional
   parameters may be defined in other specifications.

   When the header field value contains a display name, the URI
   including all URI parameters is enclosed in "<" and ">".  If no "<"
   and ">" are present, all parameters after the URI are header
   parameters, not URI parameters.  The display name can be tokens, or a
   quoted string, if a larger character set is desired.

   Even if the "display-name" is empty, the "name-addr" form MUST be
   used if the "addr-spec" contains a comma, semicolon, or question
   mark.  There may or may not be LWS between the display-name and the
   "<".

   These rules for parsing a display name, URI and URI parameters, and
   header parameters also apply for the header fields To and From.

   The compact form of the Contact header field is m (for "moved").

   Examples:

      Contact: "Mr. Watson" <sip:watson@worcester.bell-telephone.com>
         ;q=0.7; expires=3600,
         "Mr. Watson" <mailto:watson@bell-telephone.com> ;q=0.1
      m: <sips:bob@192.0.2.4>;expires=60

   Contact        =  ("Contact" / "m" ) HCOLON
                     ( STAR / (contact-param *(COMMA contact-param)))
   contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
   name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
   addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
   display-name   =  *(token LWS)/ quoted-string

   contact-params     =  c-p-q / c-p-expires
                         / contact-extension
   c-p-q              =  "q" EQUAL qvalue
   c-p-expires        =  "expires" EQUAL delta-seconds
   contact-extension  =  generic-param
   delta-seconds      =  1*DIGIT
 */

typedef struct contact_param_t
{
  str_pos_t displayName;

  str_pos_t url_str;
  SipUri* url;

  uint32_t  num_params;
  SipParamArray_t params;  /**< Contact parameters */
}contact_param_t;

#define MAX_NUM_CONTPARMS 8
typedef std::array<contact_param_t, MAX_NUM_CONTPARMS> contact_param_array_t;

class ContactHeader : public SipHeader
{
public:
  ContactHeader()
    : num_contact_parms(0), contact_parms()
  {}

  virtual ~ContactHeader() {
    for (uint32_t i = 0; i < num_contact_parms; i++)
    {
      if (contact_parms[i].url)
      {
        delete contact_parms[i].url;
        contact_parms[i].url = NULL;
      }
    }
  }

  /* Parsing utility */
  const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen);

  /* parses URI part of Contact header if main parsing is done. */
  int ParseUrlPart();

  /* both provide the value part, which can be re-formatted if the header has
     subparts or represents a multiple-header */
  std::string GetHeaderValue();
  int GetHeaderValue(std::string& value);

  /* provides the pointer to value part of the header in question.
     No any additional copy applied. */
  int GetHeaderValue(RawData& value);

  void PrintOut(std::ostringstream& buf);

  uint32_t  num_contact_parms;
  contact_param_array_t contact_parms;

};

//---------------------------------------------------------------------------
#endif // _CONTACT_HEADER_H_
