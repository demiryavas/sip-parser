/*
 * CSeqHeader.h
 *
 *  Created on: May 14, 2020
 *      Author: demir
 */

#ifndef _CSEQ_HEADER_H_
#define _CSEQ_HEADER_H_
//---------------------------------------------------------------------------

#include "SipMessage.h"
#include "SipHeader.h"

class CSeqHeader : public SipHeader
{
public:
  CSeqHeader()
    : method({ 0, 0 }), number({ 0, 0 }), cseqNum(0), sipMethod((enum sip_method)0),
    index(0)
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

  uint32_t GetCSeqNumber() { return this->cseqNum; }
  enum sip_method GetCSeqMethod() { return this->sipMethod; }

  int CompareNumber(const char* numval);
  int CompareNumber(uint32_t numval);
  int CompareMethod(const char* metval);
  int CompareMethod(enum sip_method metval);

  void PrintOut(std::ostringstream& buf);

  str_pos_t number;
  str_pos_t method;

private:
  uint32_t cseqNum;
  enum sip_method sipMethod;
  size_t index;

};

//---------------------------------------------------------------------------
#endif /* _CSEQ_HEADER_H_ */