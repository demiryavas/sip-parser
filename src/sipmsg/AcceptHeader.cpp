#include "AcceptHeader.h"
#include "Utility.h"

enum media_range_parsing_state
{
  s_mdr_dead = 1
  , s_mdr_spaces_before_value
  , s_mdr_m_type
  , s_mdr_m_type_lws
  , s_mdr_m_subtype_start
  , s_mdr_m_subtype_start_lws
  , s_mdr_m_subtype
  , s_mdr_m_subtype_lws
  , s_mdr_media_range_completed
  , s_mdr_param_start
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum media_range_parsing_state parse_media_range_char(enum media_range_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_mdr_spaces_before_value:
      if (IS_TOKEN(ch))
      {
        return s_mdr_m_type;
      }
      if (IS_LWS(ch))
      {
        return s;
      }
      break;

    case s_mdr_m_type:
      if (IS_TOKEN(ch))
      {
        return s_mdr_m_type;
      }
      if (IS_LWS(ch))
      {
        return s_mdr_m_type_lws;
      }
      if (ch == '/')
      {
        return s_mdr_m_subtype_start;
      }
      break;

    case s_mdr_m_type_lws:
      if (IS_LWS(ch))
      {
        return s_mdr_m_type_lws;
      }
      if (ch == '/')
      {
        return s_mdr_m_subtype_start;
      }
      break;

    case s_mdr_m_subtype_start:
    case s_mdr_m_subtype_start_lws:
      if (IS_LWS(ch))
      {
        return s_mdr_m_subtype_start_lws;
      }
      if (IS_TOKEN(ch))
      {
        return s_mdr_m_subtype;
      }
      break;

    case s_mdr_m_subtype:
      if (IS_TOKEN(ch))
      {
        return s_mdr_m_subtype;
      }
      if (IS_LWS(ch))
      {
        return s_mdr_m_subtype_lws;
      }
      if (ch == ';')
      {
        return s_mdr_param_start;
      }
      if (ch == ',')
      {
        return s_mdr_media_range_completed;
      }
      break;
  
    case s_mdr_m_subtype_lws:
      if (IS_LWS(ch))
      {
        return s_mdr_m_subtype_lws;
      }
      if (ch == ';')
      {
        return s_mdr_param_start;
      }
      if (ch == ',')
      {
        return s_mdr_media_range_completed;
      }
      break;
  }
  return s_mdr_dead;
}

const char* parse_media_range_part(const char* buf, size_t pos, size_t buflen, accept_range_t* accrange, int* parse_error)
{
  ParsingStatus_t result = PARSED_SUCCESSFULLY; /* be optimistic */
  enum media_range_parsing_state s = s_mdr_spaces_before_value;
  enum media_range_parsing_state prev_s = s_mdr_spaces_before_value;
  const char* mtype_mark = NULL;
  const char* msubtype_mark = NULL;

  const char* p;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_media_range_char(s, *p);

    switch (s)
    {
      case s_mdr_dead:
        *parse_error = PARSING_FAILED_STATE_DEAD;
        return p;

      case s_mdr_m_type:
        if (prev_s == s_mdr_spaces_before_value)
        {
          mtype_mark = p;
        }
        break;

      case s_mdr_m_type_lws:
        if (prev_s == s_mdr_m_type)
        {
          accrange->m_type.start = mtype_mark - buf;
          accrange->m_type.length = p - mtype_mark;
        }
        break;

      case s_mdr_m_subtype_start:
        if (prev_s == s_mdr_m_type)
        {
          accrange->m_type.start = mtype_mark - buf;
          accrange->m_type.length = p - mtype_mark;
        }
        break;

      case s_mdr_m_subtype:
        if ((prev_s == s_mdr_m_subtype_start) || (prev_s == s_mdr_m_subtype_start_lws))
        {
          msubtype_mark = p;
        }
        break;

      case s_mdr_m_subtype_lws:
        if (prev_s == s_mdr_m_subtype)
        {
          accrange->m_subtype.start = msubtype_mark - buf;
          accrange->m_subtype.length = p - msubtype_mark;
        }
        break;

      case s_mdr_param_start:
        if (prev_s == s_mdr_m_subtype)
        {
          accrange->m_subtype.start = msubtype_mark - buf;
          accrange->m_subtype.length = p - msubtype_mark;
        }
        return p;
        break;

      case s_mdr_media_range_completed:
        if (prev_s == s_mdr_m_subtype)
        {
          accrange->m_subtype.start = msubtype_mark - buf;
          accrange->m_subtype.length = p - msubtype_mark;
        }
        else if (prev_s == s_mdr_m_subtype)
        {
          /* Nothing to do (required settings already done) */
        }
        else
        {
          *parse_error = PARSING_FAILED_STATE_UNHANDLED;
        }
        return p;
        break;
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the last state to complete the job */
  switch (s)
  {
    case s_mdr_m_subtype:
      /* considered media-subtype completed */
      accrange->m_subtype.start = msubtype_mark - buf;
      accrange->m_subtype.length = p - msubtype_mark;
      break;
    case s_mdr_m_subtype_lws:
      break;

    default:
      //result = PARSING_FAILED_STATE_UNHANDLED;
      *parse_error = PARSING_FAILED_STATE_UNHANDLED;
      break;
  }

  return p;
}

const char* AcceptHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  const char* p;
  const char ch = 0;
  //uint32_t cparam_count = 0;
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
    accept_range_t* accrange = &this->accept_ranges[this->num_accept_ranges++];
    p = parse_media_range_part(buf, p - buf, buflen, accrange, &parse_error);
    if (parse_error)
    {
      this->parsing_stat = (ParsingStatus_t)parse_error;
      return p;
    }
    if (p < buf + buflen)
    {
      /* there should be parameters part or a new via-parm encountered */
      if ((*p != ';') && (*p != ','))
      {
        /* we expected ';' for parameters part or "," for multiple-header */
        this->parsing_stat = PARSING_FAILED_UNEXPECTED_CHAR;
        return p;
      }
      /* parameters part shall be first if there is */
      if (*p == ';')
      {
        p++; /* skip ';' char */
        p = parse_param_part(buf, p - buf, buflen, &accrange->params[0], MAX_NUM_PARAMS, &accrange->num_params, &parse_error, 1);
        if (parse_error)
        {
          /* TODO: Map parse_error to parsing_stat */
          this->parsing_stat = PARSING_FAILED_UNCLEAR_REASON;
          return p;
        }
      }
      if (p >= buf + buflen)
      {
        this->parsing_stat = PARSED_SUCCESSFULLY;
        return 0;
      }
      if (*p != ',')
      {
        /* we expected ',' for a new contact_param start phase */
        this->parsing_stat = PARSING_FAILED_UNEXPECTED_CHAR;
        return p;
      }
      // else let the for loop above to handle new via-parm part, ',' char will be skipped by p++ in for-loop
    }
  }

  this->parsing_stat = (parse_error) ? PARSING_FAILED_UNCLEAR_REASON : PARSED_SUCCESSFULLY;
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string AcceptHeader::GetHeaderValue()
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
  for (int i = 0; i < this->num_accept_ranges; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      sbuf.append(1, ',');
    }
    accept_range_t* accrange = &this->accept_ranges[i];

    /* check for mandatory parts if exist */
    if (!(this->rawdata._length) || !(accrange->m_type.length) || !(accrange->m_subtype.length))
    {
      return "";
    }

    size_t length = (size_t)this->rawdata._length;
    sbuf.reserve(length);
    sbuf.append((const char*)this->rawdata._data + accrange->m_type.start, accrange->m_type.length);
    sbuf.append(1, '/');
    sbuf.append((const char*)this->rawdata._data + accrange->m_subtype.start, accrange->m_subtype.length);
    for (int i = 0; i < accrange->num_params; i++)
    {
      sbuf.append(1, ';');
      sbuf.append((const char*)this->rawdata._data + accrange->params[i].type.start, accrange->params[i].type.length);
      if (accrange->params[i].value.length)
      {
        sbuf.append(1, '=');
        sbuf.append((const char*)this->rawdata._data + accrange->params[i].value.start, accrange->params[i].value.length);
      }
    }
  }
  return sbuf;
}

int AcceptHeader::GetHeaderValue(std::string& value)
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
  for (int i = 0; i < this->num_accept_ranges; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      value.append(1, ',');
    }
    accept_range_t* accrange = &this->accept_ranges[i];

    /* check for mandatory parts if exist */
    if (!(this->rawdata._length) || !(accrange->m_type.length) || !(accrange->m_subtype.length))
    {
      value = "";
      return 1;
    }

    size_t length = (size_t)this->rawdata._length;
    value.reserve(length);
    value.append((const char*)this->rawdata._data + accrange->m_type.start, accrange->m_type.length);
    value.append(1, '/');
    value.append((const char*)this->rawdata._data + accrange->m_subtype.start, accrange->m_subtype.length);
    for (int i = 0; i < accrange->num_params; i++)
    {
      value.append(1, ';');
      value.append((const char*)this->rawdata._data + accrange->params[i].type.start, accrange->params[i].type.length);
      if (accrange->params[i].value.length)
      {
        value.append(1, '=');
        value.append((const char*)this->rawdata._data + accrange->params[i].value.start, accrange->params[i].value.length);
      }
    }
  }
  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int AcceptHeader::GetHeaderValue(RawData& value)
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

void AcceptHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Accept Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }

  for (int i = 0; i < this->num_accept_ranges; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      buf << ',';
    }
    accept_range_t* accparam = &this->accept_ranges[i];

    buf << "media-type    : " << std::string((const char*)this->rawdata._data + accparam->m_type.start, accparam->m_type.length) << std::endl;
    buf << "media-subtype : " << std::string((const char*)this->rawdata._data + accparam->m_subtype.start, accparam->m_subtype.length) << std::endl;

    if (accparam->num_params)
    {
      buf << "---------- Parameters ----------\n";
      for (int i = 0; i < accparam->num_params; i++)
      {
        buf << std::string((const char*)this->rawdata._data + accparam->params[i].type.start, accparam->params[i].type.length);
        if (accparam->params[i].value.length)
        {
          buf << '=';
          buf << std::string((const char*)this->rawdata._data + accparam->params[i].value.start, accparam->params[i].value.length);
          buf << std::endl;
        }
      }
    }
    buf << "----------------\n";
    buf << "Accept: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
    buf << "---------------------------------------\n";
  }
}
