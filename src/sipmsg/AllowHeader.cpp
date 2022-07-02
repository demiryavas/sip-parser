#include "AllowHeader.h"


/* TODO: Copied from sipparcer.c. A common place could be found to prevent re-definiton */
static const char* method_strings[] =
{
#define XX(num, name, string) #string,
  SIP_METHOD_MAP(XX)
#undef XX
};

const char* AllowHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  const char* p = NULL;
  char ch = 0;
  int parse_error = 0;
  const char* meth_mark;
  const char* matcher;
  str_pos_t* curr_meth;

  if (buflen == 0)
  {
    this->parsing_stat = PARSING_FAILED_NO_DATA;
    return buf;
  }
  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = buflen;
  this->rawdata._pos = pos;

  p = buf + pos;

new_method:
  while ((p < buf + buflen) && IS_LWS(*p))
  {
    p++;
  }
  if (p >= buf + buflen)
  {
    /* Empty Allow header is allowed */
    this->parsing_stat = PARSED_SUCCESSFULLY;
    return 0;
  }
  ch = *p;
  uint32_t method = (enum sip_method)0;
  uint32_t index = 1;
  switch (ch) {
    case 'A': method = SIP_ACK; break;
    case 'B': method = SIP_BYE; break;
    case 'C': method = SIP_CANCEL; break;
    case 'I': method = SIP_INFO; /* or INVITE */ break;
    case 'M': method = SIP_MESSAGE; break;
    case 'N': method = SIP_NOTIFY; break;
    case 'O': method = SIP_OPTIONS; break;
    case 'P': method = SIP_PRACK;  /* or PUBLISH */ break;
    case 'R': method = SIP_REFER; /* or REGISTER */ break;
    case 'S': method = SIP_SUBSCRIBE; break;
    case 'U': method = SIP_UPDATE; break;
    default:
      this->parsing_stat = PARSING_FAILED_INVALID_METHOD;
      return p;
  }
  curr_meth = &allow_methods[this->num_allow_methods++];
  meth_mark = p;
  p++; /* skip first char */

  for (; p < buf + buflen; p++)
  {
    ch = *p;

    matcher = method_strings[method];
    if (IS_LWS(*p) && matcher[index] == '\0')
    {
      /* complete the collection a method */
      curr_meth->start = meth_mark - buf;
      curr_meth->length = p - meth_mark; 
      this->allow_method_enums[this->num_allow_methods - 1] = (enum sip_method)method;
      while ((p < buf + buflen) && IS_LWS(*p))
      {
        p++;
      }
      if ((*p) == ',')
      {
        p++;
      }
      goto new_method;
    }
    if (ch == ',' && matcher[index] == '\0')
    {
      /* complete the collection a method */
      curr_meth->start = meth_mark - buf;
      curr_meth->length = p - meth_mark;
      this->allow_method_enums[this->num_allow_methods - 1] = (enum sip_method)method;
      p++;
      goto new_method;
    }
    else if (ch == matcher[index]) 
    {
      ; /* nothing to do */
    }
    else if ((ch >= 'A' && ch <= 'Z') || ch == '-') 
    {
      switch (method << 16 | index << 8 | ch) 
      {
#define XX(meth, pos, ch, new_meth) \
        case (SIP_##meth << 16 | pos << 8 | ch): \
          method = SIP_##new_meth; break;

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

    ++index;
  }
  this->parsing_stat = (parse_error) ? PARSING_FAILED_UNCLEAR_REASON : PARSED_SUCCESSFULLY;
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string AllowHeader::GetHeaderValue()
{
  /* check for mandatory parts if exist */
  if (!this->rawdata._length)
  {
    return "";
  }
  if (this->parsing_stat == NOT_PARSED_YET)
  {
    ParseHeader((const char*)this->rawdata._data, 0, this->rawdata._length);
    /* it also updated the parsing status */
    if (this->parsing_stat != PARSED_SUCCESSFULLY)
    {
      return "";
    }
  }
  size_t length = (size_t)this->rawdata._length;
  std::string sbuf;
  sbuf.reserve(length);
  for (int i = 0; i < this->num_allow_methods; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      sbuf.append(", ", 2);
    }
    str_pos_t* meth = &this->allow_methods[i];
    sbuf.append((const char*)this->rawdata._data + meth->start, meth->length);
  }
  return sbuf;
}

int AllowHeader::GetHeaderValue(std::string& value)
{
  /* check for mandatory parts if exist */
  if (!this->rawdata._length)
  {
    value = "";
    return 1;
  }
  if (this->parsing_stat == NOT_PARSED_YET)
  {
    ParseHeader((const char*)this->rawdata._data, 0, this->rawdata._length);
    /* it also updated the parsing status */
    if (this->parsing_stat != PARSED_SUCCESSFULLY)
    {
      value = "";
      return 1;
    }
  }
  size_t length = (size_t)this->rawdata._length;
  value.reserve(length);
  for (int i = 0; i < this->num_allow_methods; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      value.append(", ", 2);
    }
    str_pos_t* meth = &this->allow_methods[i];
    value.append((const char*)this->rawdata._data + meth->start, meth->length);
  }
  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int AllowHeader::GetHeaderValue(RawData& value)
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

void AllowHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Allow Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }
  for (int i = 0; i < this->num_allow_methods; i++)
  {
    str_pos_t* meth = &this->allow_methods[i];
    buf << '[' << i << "]: " << std::string((const char*)this->rawdata._data + meth->start, meth->length) 
        << " (" << this->allow_method_enums[i] << ')' << std::endl;
  }
  buf << "----------------\n";
  buf << "Allow: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}
