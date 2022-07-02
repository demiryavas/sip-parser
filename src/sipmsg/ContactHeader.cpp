
#include "ContactHeader.h"
#include "Utility.h"

/* Parsing utility */
const char* ContactHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  const char* p;
  const char ch = 0;
  int parse_error = 0;

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
    contact_param_t* contparam = &this->contact_parms[this->num_contact_parms++];
    p = parse_name_addr_part(buf, p - buf, buflen, &contparam->displayName, &contparam->url_str, &parse_error, 1);
    if (parse_error != 0)
    {
      this->parsing_stat = PARSING_FAILED_UNCLEAR_REASON;
      return p;
    }
    if (p < buf + buflen)
    {
      /* possibly we are in parameters part. Search for param-start position. i.e. ';' char */
      while ((p < buf + buflen) && IS_LWS(*p))
      {
        p++;
      }
      if (p >= buf + buflen)
      {
        /* all space in end-of-line are skipped and no further data. So parsing is completed */
        this->parsing_stat = PARSED_SUCCESSFULLY;
        return 0;
      }
      /* there should be parameters part or a new contact-parm encountered */
      if ((*p != ';') && (*p != ','))
      {
        /* we expected ';' for parameters part or "," for multiple-header */
        this->parsing_stat = PARSING_FAILED_UNEXPECTED_CHAR;
        return p;
      }
      /* parameters part shall be first if there is */
      if (*p == ';')
      {
        p++; /* skip ';' */
        parse_error = 0; /* reset */
        p = parse_param_part(buf, p - buf, buflen, &contparam->params[0], MAX_NUM_PARAMS, &contparam->num_params, &parse_error, 1);
        if (parse_error)
        {
          /* TODO: Map parse_error to 'ParsingStatus_t" */
          this->parsing_stat = PARSING_FAILED_UNCLEAR_REASON;
          return p;
        }
      }
      if (p >= buf + buflen)
      {
        this->parsing_stat = PARSED_SUCCESSFULLY;
        return 0;
      }
      while ((p < buf + buflen) && IS_LWS(*p))
      {
        p++;
      }
      /* check for multiple contact-params separated by ',' */
      if (p < buf + buflen)
      {
        if (*p != ',')
        {
          /* we expected ',' for a new contact_param start phase */
          this->parsing_stat = PARSING_FAILED_UNEXPECTED_CHAR;
          return p; 
        }
      }
    }
  }
  this->parsing_stat = (parse_error) ? PARSING_FAILED_UNCLEAR_REASON : PARSED_SUCCESSFULLY;
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string ContactHeader::GetHeaderValue()
{
  /* check for mandatory parts if exist */
  if (!this->rawdata._length)
  {
    return "";
  }
  size_t length = (size_t)this->rawdata._length;
  std::string sbuf;
  sbuf.reserve(length);
  if (this->parsing_stat == NOT_PARSED_YET)
  {
    ParseHeader((const char*)this->rawdata._data, 0, this->rawdata._length);
    /* it also updated the parsing status */
    if (this->parsing_stat != PARSED_SUCCESSFULLY)
    {
      return "";
    }
  }

  for (int i = 0; i < this->num_contact_parms; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      sbuf.append(1, ',');
    }
    contact_param_t* contparam = &this->contact_parms[i];
    if (contparam->displayName.length)
    {
      sbuf.append((const char*)this->rawdata._data + contparam->displayName.start, contparam->displayName.length);
      sbuf.append(1, ' ');
    }
    sbuf.append((const char*)this->rawdata._data + contparam->url_str.start, contparam->url_str.length);

    for (uint32_t i = 0; i < contparam->num_params; i++)
    {
      sbuf.append(1, ';');
      sbuf.append((const char*)this->rawdata._data + contparam->params[i].type.start, contparam->params[i].type.length);
      if (contparam->params[i].value.length)
      {
        sbuf.append(1, '=');
        sbuf.append((const char*)this->rawdata._data + contparam->params[i].value.start, contparam->params[i].value.length);
      }
    }
  }
  return sbuf;
}

int ContactHeader::GetHeaderValue(std::string& value)
{
  /* check for mandatory parts if exist */
  if (!this->rawdata._length)
  {
    return 1;
  }
  size_t length = (size_t)this->rawdata._length;
  value.reserve(length);
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

  for (int i = 0; i < this->num_contact_parms; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      value.append(1, ',');
    }
    contact_param_t* contparam = &this->contact_parms[i];
    if (contparam->displayName.length)
    {
      value.append((const char*)this->rawdata._data + contparam->displayName.start, contparam->displayName.length);
      value.append(1, ' ');
    }
    value.append((const char*)this->rawdata._data + contparam->url_str.start, contparam->url_str.length);

    for (uint32_t i = 0; i < contparam->num_params; i++)
    {
      value.append(1, ';');
      value.append((const char*)this->rawdata._data + contparam->params[i].type.start, contparam->params[i].type.length);
      if (contparam->params[i].value.length)
      {
        value.append(1, '=');
        value.append((const char*)this->rawdata._data + contparam->params[i].value.start, contparam->params[i].value.length);
      }
    }
  }
  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int ContactHeader::GetHeaderValue(RawData& value)
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

void ContactHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Contact Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }

  for (int i = 0; i < this->num_contact_parms; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      buf << ',';
    }
    contact_param_t* contparam = &this->contact_parms[i];
    buf << "display-name : " << std::string((const char*)this->rawdata._data + contparam->displayName.start, contparam->displayName.length) << std::endl;
    buf << "url          : " << std::string((const char*)this->rawdata._data + contparam->url_str.start, contparam->url_str.length) << std::endl;
    if (contparam->num_params)
    {
      buf << "---------- Parameters ----------\n";
      for (uint32_t i = 0; i < contparam->num_params; i++)
      {
        buf << std::string((const char*)this->rawdata._data + contparam->params[i].type.start, contparam->params[i].type.length);
        if (contparam->params[i].value.length)
        {
          buf << '=';
          buf << std::string((const char*)this->rawdata._data + contparam->params[i].value.start, contparam->params[i].value.length);
        }
        buf << std::endl;
      }
    }
    if (contparam->url)
    {
      buf << "......Detailed URI.......\n";
      contparam->url->PrintOut(buf);
    }
    buf << "----------------\n";
    buf << "Contact: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
    buf << "---------------------------------------\n";
  }
}
