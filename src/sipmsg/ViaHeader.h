/*
 * ViaHeader.h
 *
 *  Created on: May 16, 2020
 *      Author: demir
 */

#ifndef _VIA_HEADER_H_
#define _VIA_HEADER_H_
 //---------------------------------------------------------------------------

#include "SipMessage.h"
#include "SipHeader.h"

typedef struct via_param_t
{
  str_pos_t protocol;        /**< Protocol used by SIP Agent */
  str_pos_t version;         /**< Version of the protocol */
  str_pos_t transport;       /**< UDP, TCP, TLS, SCTP, ... */
  str_pos_t host;            /**< Host where to send responses */
  str_pos_t port;            /**< Port where to send responses */
  str_pos_t branch;          /**< Branch parameter for quick access */
  uint32_t  num_params;
  SipParamArray_t params;    /**< Via parameters */
} via_param_t;

#define MAX_NUM_VIAPARMS 8
typedef std::array<via_param_t, MAX_NUM_VIAPARMS> via_param_array_t;

class ViaHeader : public SipHeader
{
public:
  ViaHeader()
    : num_via_parms(0), via_parms()
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

  uint32_t num_via_parms;
  via_param_array_t via_parms;

};

//---------------------------------------------------------------------------
#endif /* _VIA_HEADER_H_ */