#include "ContentTypeHeader.h"
#include "Utility.h"
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

enum cont_hdr_parsing_state
{
  s_hdr_dead = 1
  , s_hdr_spaces_before_value
  , s_hdr_m_type
  , s_hdr_m_type_lws
  , s_hdr_m_subtype_start
  , s_hdr_m_subtype_start_lws
  , s_hdr_m_subtype
  , s_hdr_m_subtype_lws
  , s_hdr_param_start
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum cont_hdr_parsing_state parse_header_char(enum cont_hdr_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_hdr_spaces_before_value:
      if (IS_TOKEN(ch))
      {
        return s_hdr_m_type;
      }
      break;

    case s_hdr_m_type:
      if (IS_TOKEN(ch))
      {
        return s_hdr_m_type;
      }
      if (IS_LWS(ch))
      {
        return s_hdr_m_type_lws;
      }
      if (ch == '/')
      {
        return s_hdr_m_subtype_start;
      }
      break;

    case s_hdr_m_type_lws:
      if (IS_LWS(ch))
      {
        return s_hdr_m_type_lws;
      }
      if (ch == '/')
      {
        return s_hdr_m_subtype_start;
      }
      break;

    case s_hdr_m_subtype_start:
    case s_hdr_m_subtype_start_lws:
      if (IS_LWS(ch))
      {
        return s_hdr_m_subtype_start_lws;
      }
      if (IS_TOKEN(ch))
      {
        return s_hdr_m_subtype;
      }
      break;

    case s_hdr_m_subtype:
      if (IS_TOKEN(ch))
      {
        return s_hdr_m_subtype;
      }
      if (IS_LWS(ch))
      {
        return s_hdr_m_subtype_lws;
      }
      if (ch == ';')
      {
        return s_hdr_param_start;
      }
      break;
  
    case s_hdr_m_subtype_lws:
      if (IS_LWS(ch))
      {
        return s_hdr_m_subtype_lws;
      }
      if (ch == ';')
      {
        return s_hdr_param_start;
      }
      break;
  }
  return s_hdr_dead;
}

const char* ContentTypeHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  ParsingStatus_t result = PARSED_SUCCESSFULLY; /* be optimistic */
  enum cont_hdr_parsing_state s = s_hdr_spaces_before_value;
  enum cont_hdr_parsing_state prev_s = s_hdr_spaces_before_value;
  const char* mtype_mark = NULL;
  const char* msubtype_mark = NULL;

  int parse_error = 0;
  const char* p;

  if (buflen == 0)
  {
    this->parsing_stat = PARSING_FAILED_NO_DATA;
    return buf;
  }

  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = (unsigned int)buflen;
  this->rawdata._pos = (unsigned int)pos;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_header_char(s, *p);

    switch (s)
    {
      case s_hdr_dead:
        this->parsing_stat = PARSING_FAILED_STATE_DEAD;
        return p;

      case s_hdr_m_type:
        if (prev_s == s_hdr_spaces_before_value)
        {
          mtype_mark = p;
        }
        break;

      case s_hdr_m_type_lws:
        if (prev_s == s_hdr_m_type)
        {
          this->m_type.start = mtype_mark - buf;
          this->m_type.length = p - mtype_mark;
        }
        break;

      case s_hdr_m_subtype_start:
        if (prev_s == s_hdr_m_type)
        {
          this->m_type.start = mtype_mark - buf;
          this->m_type.length = p - mtype_mark;
        }
        break;

      case s_hdr_m_subtype:
        if ((prev_s == s_hdr_m_subtype_start) || (prev_s == s_hdr_m_subtype_start_lws))
        {
          msubtype_mark = p;
        }
        break;

      case s_hdr_m_subtype_lws:
        if (prev_s == s_hdr_m_subtype)
        {
          this->m_subtype.start = msubtype_mark - buf;
          this->m_subtype.length = p - msubtype_mark;
        }
        break;

      case s_hdr_param_start:
        if (prev_s == s_hdr_m_subtype)
        {
          this->m_subtype.start = msubtype_mark - buf;
          this->m_subtype.length = p - msubtype_mark;
        }

        p++; // skip ';'
        p = parse_param_part(buf, p - buf, buflen, &this->params[0], MAX_NUM_PARAMS, &this->num_params, &parse_error, 0);
        //if (p == NULL)
        if (parse_error)
        {
          /* TODO: Map parse_error to parsing_stat */
          this->parsing_stat = PARSING_FAILED_UNCLEAR_REASON;
          return p;
        }
        //printf("Number of parameters = %u and pos = %s", this->num_params, p);
        break;

    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the last state to complete the job */
  switch (s)
  {
    case s_hdr_m_subtype:
      /* considered media-subtype completed */
      this->m_subtype.start = msubtype_mark - buf;
      this->m_subtype.length = p - msubtype_mark;
      break;
    case s_hdr_param_start:
      /* In the case of external-parsing of parameter part */
      break;

    default:
      result = PARSING_FAILED_STATE_UNHANDLED;
      break;
  }

  this->parsing_stat = result;
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string ContentTypeHeader::GetHeaderValue()
{
  if (!(this->rawdata._length) || !(this->m_type.length) || !(this->m_subtype.length))
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
  sbuf.append((const char*)this->rawdata._data + this->m_type.start, this->m_type.length);
  sbuf.append(1, '/');
  sbuf.append((const char*)this->rawdata._data + this->m_subtype.start, this->m_subtype.length);
  for (int i = 0; i < this->num_params; i++)
  {
    sbuf.append(1, ';');
    sbuf.append((const char*)this->rawdata._data + this->params[i].type.start, this->params[i].type.length);
    if (this->params[i].value.length)
    {
      sbuf.append(1, '=');
      sbuf.append((const char*)this->rawdata._data + this->params[i].value.start, this->params[i].value.length);
    }
  }

  return sbuf;
}

int ContentTypeHeader::GetHeaderValue(std::string& value)
{
  if (!(this->rawdata._length) || !(this->m_type.length) || !(this->m_subtype.length))
  {
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
  value.append((const char*)this->rawdata._data + this->m_type.start, this->m_type.length);
  value.append(1, '/');
  value.append((const char*)this->rawdata._data + this->m_subtype.start, this->m_subtype.length);
  for (int i = 0; i < this->num_params; i++)
  {
    value.append(1, ';');
    value.append((const char*)this->rawdata._data + this->params[i].type.start, this->params[i].type.length);
    if (this->params[i].value.length)
    {
      value.append(1, '=');
      value.append((const char*)this->rawdata._data + this->params[i].value.start, this->params[i].value.length);
    }
  }
  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int ContentTypeHeader::GetHeaderValue(RawData& value)
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

void ContentTypeHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Content-Type Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }
  buf << "media-type    : " << std::string((const char*)this->rawdata._data + this->m_type.start, this->m_type.length) << std::endl;
  buf << "media-subtype : " << std::string((const char*)this->rawdata._data + this->m_subtype.start, this->m_subtype.length) << std::endl;
  if (this->num_params > 0)
  {
    buf << "---------- Parameters ----------\n";
    for (int i = 0; i < this->num_params; i++)
    {
      buf << std::string((const char*)this->rawdata._data + this->params[i].type.start, this->params[i].type.length);
      if (this->params[i].value.length)
      {
        buf << '=';
        buf << std::string((const char*)this->rawdata._data + this->params[i].value.start, this->params[i].value.length);
        buf << std::endl;
      }
    }
  }

  buf << "----------------\n";
  buf << "Content-Type: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}