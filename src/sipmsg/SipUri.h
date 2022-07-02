/*
 * SipUri.h
 *
 *  Created on: Apr 19, 2020
 *      Author: demir
 */

#ifndef SIPURI_H_
#define SIPURI_H_
 //---------------------------------------------------------------------------
#include "SipMessage.h" // TODO: SipMessage.h shall be removed by moving 
                        // definitions, like str_pos_t, to a common place 
#include "RawData.h"

#include <sstream>      // std::ostringstream

/* examples: (Copied from osip_uri.c)
   sip:j.doe@big.com;maddr=239.255.255.1;ttl=15
   sip:j.doe@big.com
   sip:j.doe:secret@big.com;transport=tcp
   sip:j.doe@big.com?subject=project
   sip:+1-212-555-1212:1234@gateway.com;user=phone
   sip:1212@gateway.com
   sip:alice@10.1.2.3
   sip:alice@example.com
   sip:alice@registrar.com;method=REGISTER

   NOT EQUIVALENT:
   SIP:JUSER@ExAmPlE.CoM;Transport=udp
   sip:juser@ExAmPlE.CoM;Transport=UDP
*/

typedef struct sip_uri_t
{
  str_pos_t scheme;                          /**< Uri Scheme (sip or sips) */
  str_pos_t username;                        /**< Username */
  str_pos_t password;                        /**< Password */
  str_pos_t host;                            /**< Domain */
  str_pos_t port;                            /**< Port number */
  int num_params;
  SipParamArray_t urlParams;                 /**< Uri parameters */

  int num_headers;
  SipHeadersMinArray_t urlHeaders;           /**< Uri headers */

  str_pos_t others;                          /**< Space for other url schemes. (http, mailto...) */
} sip_uri_t;

class SipUri
{
public:
  SipUri()
    : uri(), rawdata()
  {}

  ~SipUri() { /* To be implemented when data relationship is clear */ }

  sip_uri_t uri;

  RawData rawdata;

  int ParseUri(const char* buf, size_t pos, size_t buflen);

  int ParseHostPortPair(size_t pos, const char* hostport, size_t length);
  int ParseUriHeaders(const char* buf, size_t length);
  int ParseUriParams(const char* buf, size_t length);

  void PrintOut(std::ostringstream& buf);
};

//---------------------------------------------------------------------------
#endif /* SIPURI_H_ */
