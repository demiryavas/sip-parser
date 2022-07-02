/*
 * CSeqHeader.cpp
 *
 *  Created on: May 14, 2020
 *      Author: demir
 */

#include "CSeqHeader.h"

/* The CSeq header field serves as a way to identify and order
   transactions.  It consists of a sequence number and a method.  The
   method MUST match that of the request.  For non-REGISTER requests
   outside of a dialog, the sequence number value is arbitrary.  The
   sequence number value MUST be expressible as a 32-bit unsigned
   integer and MUST be less than 2**31.  As long as it follows the above
   guidelines, a client may use any mechanism it would like to select
   CSeq header field values.

   Example:
      CSeq: 4711 INVITE

   CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method

   LWS  =  [*WSP CRLF] 1*WSP ; linear whitespace
   WSP  =  SP/HTAB ; white space
 */

static const char* method_strings[] =
{
#define XX(num, name, string) #string,
  SIP_METHOD_MAP(XX)
#undef XX
};

enum hdr_parsing_state
{ s_hdr_dead = 1
  , s_hdr_spaces_before_value
  , s_hdr_number
  , s_hdr_number_lws
  , s_hdr_method
  , s_hdr_method_ws
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum hdr_parsing_state parse_header_char(enum hdr_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_hdr_spaces_before_value:
      if (IS_DIGIT(ch))
      {
        return s_hdr_number;
      }
      if (IS_LWS(ch))
      {
        return s;
      }
      break;

    case s_hdr_number:
      if (IS_DIGIT(ch))
      {
        return s_hdr_number;
      }
      if (IS_LWS(ch))
      {
        return s_hdr_number_lws;
      }
      break;

    case s_hdr_number_lws:
      if (IS_LWS(ch))
      {
        return s_hdr_number_lws;
      }
      if (ch >= 'A' && ch <= 'Z')
      {
        /* Receiving a char as a possible SIP method */
        return s_hdr_method;
      }
      break;

    case s_hdr_method:
      if (ch >= 'A' && ch <= 'Z')
      {
        return s_hdr_method;
      }
      if ((ch == ' ') || (ch == '\t'))
      {
        return s_hdr_method_ws;
      }
      break;

    case s_hdr_method_ws:
      if ((ch == ' ') || (ch == '\t'))
      {
        return s_hdr_method_ws;
      }
      break;
  }

  return s_hdr_dead;
}

const char* CSeqHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  enum hdr_parsing_state s = s_hdr_spaces_before_value;
  enum hdr_parsing_state prev_s = s_hdr_spaces_before_value;
  const char* cseqnum_mark = NULL;
  const char* cseqmethod_mark = NULL;

  const char* p;

  if (buflen == 0)
  {
    this->parsing_stat = PARSING_FAILED_NO_DATA;
    return buf;
  }

  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = buflen;
  this->rawdata._pos = pos;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_header_char(s, *p);

    switch (s)
    {
      case s_hdr_dead:
        this->parsing_stat = PARSING_FAILED_STATE_DEAD;
        return p;

      case s_hdr_number:
        if (prev_s == s_hdr_spaces_before_value)
        {
          char ch = *p;
          this->cseqNum = ch - '0';
          cseqnum_mark = p;
        }
        else
        {
          //uint64_t t;
          uint32_t t;
          char ch = *p;

          t = this->cseqNum;
          t *= 10;
          t += ch - '0';
          /* TODO: Use 'unlikely' approach */
          if (t > UINT_MAX)
          {
            this->parsing_stat = PARSING_FAILED_MAX_RANGE;
            return p;
          }
          this->cseqNum = t;
        }
        break;

      case s_hdr_number_lws:
        if (prev_s == s_hdr_number)
        {
          this->number.start = (uint32_t)(cseqnum_mark - buf);
          this->number.length = (uint32_t)(p - cseqnum_mark);
        }
        break;

      case s_hdr_method:
        if (prev_s == s_hdr_number_lws)
        {
          /* first char of SIP method */
          cseqmethod_mark = p;
          /* Receiving a char as a possible SIP method */
          this->sipMethod = (enum sip_method) 0;
          this->index = 1;
          char ch = *p;
          switch (ch) 
          {
            case 'A': this->sipMethod = SIP_ACK; break;
            case 'B': this->sipMethod = SIP_BYE; break;
            case 'C': this->sipMethod = SIP_CANCEL; break;
            case 'I': this->sipMethod = SIP_INFO; /* or INVITE */ break;
            case 'M': this->sipMethod = SIP_MESSAGE; break;
            case 'N': this->sipMethod = SIP_NOTIFY; break;
            case 'O': this->sipMethod = SIP_OPTIONS; break;
            case 'P': this->sipMethod = SIP_PRACK;  /* or PUBLISH */ break;
            case 'R': this->sipMethod = SIP_REFER; /* or REGISTER */ break;
            case 'S': this->sipMethod = SIP_SUBSCRIBE; break;
            case 'U': this->sipMethod = SIP_UPDATE; break;
            default:
              this->parsing_stat = PARSING_FAILED_INVALID_METHOD;
              return p; 
          }
        }
        else
        {
          const char* matcher;
          char ch = *p;

          matcher = method_strings[this->sipMethod];
          /* TODO: Use 'unlikely' logic here */
          if (IS_LWS(ch) && matcher[index] == '\0')
          {
            this->method.start = (uint32_t)(cseqmethod_mark - buf);
            this->method.length = (uint32_t)(p - cseqmethod_mark);
            this->parsing_stat = PARSED_SUCCESSFULLY;
            return p;
          }
          if (ch == matcher[this->index])
          {
            ; /* seems matching is OK */
          }
          else if (ch >= 'A' && ch <= 'Z') /* TODO: we may have this check char-parser */
          {
            switch (this->sipMethod << 16 | this->index << 8 | ch)
            {
#define XX(meth, pos, ch, new_meth) \
              case (SIP_##meth << 16 | pos << 8 | ch): \
                this->sipMethod = SIP_##new_meth; break;

                XX(INFO,  2, 'V', INVITE)
                XX(PRACK, 1, 'U', PUBLISH)
                XX(REFER, 2, 'G', REGISTER)
#undef XX
              default:
                this->parsing_stat = PARSING_FAILED_INVALID_METHOD;
                return p;
            }
          }
          else
          {
            this->parsing_stat = PARSING_FAILED_INVALID_METHOD;
            return p;
          }
          ++this->index;
          break;
        }

      case s_hdr_method_ws:
        if (prev_s == s_hdr_method)
        {
          this->method.start = (uint32_t)(cseqmethod_mark - buf);
          this->method.length = (uint32_t)(p - cseqmethod_mark);
        }
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the last state to complete the job */
  if (s == s_hdr_method)
  {
    /* header parsing has been completed when parsing method part. 
       Check to see if we are end of method string also */
    const char* matcher = method_strings[this->sipMethod];
    if (matcher[this->index] == '\0')
    {
      this->method.start = (uint32_t)(cseqmethod_mark - buf);
      this->method.length = (uint32_t)(p - cseqmethod_mark);
      this->parsing_stat = PARSED_SUCCESSFULLY;
    }
    else
    {
      this->parsing_stat = PARSING_FAILED_INVALID_METHOD;
    }
    return p;
  }
  else if (s == s_hdr_method_ws)
  {
    /* ended after collecting method */
    const char* matcher = method_strings[this->sipMethod];
    if (matcher[this->index] == '\0')
    {
      this->parsing_stat = PARSED_SUCCESSFULLY;
    }
    else
    {
      this->parsing_stat = PARSING_FAILED_INVALID_METHOD;
    }
    return p;
  }

  this->parsing_stat = PARSING_FAILED_STATE_UNHANDLED; /* Un-handled success state flow. */
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string CSeqHeader::GetHeaderValue()
{
  if (!(this->rawdata._length) || !(this->number.length) || !(this->method.length))
  {
    return "";
  }
  size_t length = (size_t)this->number.length + this->method.length + 1;
  std::string sbuf;
  sbuf.reserve(length);
  sbuf.append((const char*)this->rawdata._data + this->number.start, this->number.length);
  sbuf.append(1, ' ');
  sbuf.append((const char*)this->rawdata._data + this->method.start, this->method.length);
 
  return sbuf;
}

int CSeqHeader::GetHeaderValue(std::string& value)
{
  if (!(this->rawdata._length) || !(this->number.length) || !(this->method.length))
  {
    return 1;
  }
  size_t length = (size_t)this->number.length + this->method.length + 1;
  value.reserve(length);
  value.append((const char*)this->rawdata._data + this->number.start, this->number.length);
  value.append(1, ' ');
  value.append((const char*)this->rawdata._data + this->method.start, this->method.length);

  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int CSeqHeader::GetHeaderValue(RawData& value)
{
  if (!this->rawdata._length)
  {
    return 1;
  }
  value._data = this->rawdata._data;
  value._length = this->rawdata._length;
  value._pos = this->rawdata._pos;

  return 0;
}

int CSeqHeader::CompareNumber(const char* numval)
{
  if (!(this->rawdata._length) || !(this->number.length))
  {
    return 1;
  }
  return ::memcmp(numval, this->rawdata._data + this->number.start, this->number.length);
}

int CSeqHeader::CompareNumber(uint32_t numval)
{
  return (numval == this->cseqNum);
}

int CSeqHeader::CompareMethod(const char* metval)
{
  if (!(this->rawdata._length) || !(this->method.length))
  {
    return 1;
  }
  return ::memcmp(metval, this->rawdata._data + this->method.start, this->method.length);
}

int CSeqHeader::CompareMethod(enum sip_method metval)
{
  return (metval == this->sipMethod);
}

void CSeqHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- CSEQ Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }
  buf << "number : " << std::string((const char*)this->rawdata._data + this->number.start, this->number.length) << std::endl;
  buf << "method : " << std::string((const char*)this->rawdata._data + this->method.start, this->method.length) << std::endl;
  buf << "--- calculated -------\n";
  buf << "number : " << this->cseqNum << std::endl;
  buf << "method : " << this->sipMethod << " (" << std::string((const char*)this->rawdata._data + this->method.start, this->method.length)
                     << '/' << method_strings[this->sipMethod] << ')' << std::endl;

  buf << "----------------\n";
  buf << "CSeq: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}