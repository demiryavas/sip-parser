#include "AcceptLanguageHeader.h"
#include "Utility.h"


enum accept_language_parsing_state
{
  s_lang_dead = 1
  , s_lang_spaces_before_value
  , s_lang_coding
  , s_lang_coding_lws
  , s_lang_coding_completed
  , s_lang_param_start
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum accept_language_parsing_state parse_language_range_char(enum accept_language_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_lang_spaces_before_value:
      if (IS_TOKEN(ch))
      {
        return s_lang_coding;
      }
      if (IS_LWS(ch))
      {
        return s;
      }
      break;

    case s_lang_coding:
      if (IS_TOKEN(ch))
      {
        return s_lang_coding;
      }
      if (IS_LWS(ch))
      {
        return s_lang_coding_lws;
      }
      if (ch == ';')
      {
        return s_lang_param_start;
      }
      if (ch == ',')
      {
        return s_lang_coding_completed;
      }
      break;

    case s_lang_coding_lws:
      if (IS_LWS(ch))
      {
        return s_lang_coding_lws;
      }
      if (ch == ';')
      {
        return s_lang_param_start;
      }
      if (ch == ',')
      {
        return s_lang_coding_completed;
      }
      break;
  }
  return s_lang_dead;
}

const char* parse_language_range_part(const char* buf, size_t pos, size_t buflen, accept_language_t* lang, int* parse_error)
{
  ParsingStatus_t result = PARSED_SUCCESSFULLY; /* be optimistic */
  enum accept_language_parsing_state s = s_lang_spaces_before_value;
  enum accept_language_parsing_state prev_s = s_lang_spaces_before_value;
  const char* coding_mark = NULL;

  const char* p;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_language_range_char(s, *p);

    switch (s)
    {
      case s_lang_dead:
        *parse_error = PARSING_FAILED_STATE_DEAD;
        return p;

      case s_lang_coding:
        if (prev_s == s_lang_spaces_before_value)
        {
          coding_mark = p;
        }
        break;

      case s_lang_coding_lws:
        if (prev_s == s_lang_coding)
        {
          lang->language_range.start = coding_mark - buf;
          lang->language_range.length = p - coding_mark;
        }
        break;

      case s_lang_param_start:
        if (prev_s == s_lang_coding)
        {
          lang->language_range.start = coding_mark - buf;
          lang->language_range.length = p - coding_mark;
        }
        return p;
        break;

      case s_lang_coding_completed:
        if (prev_s == s_lang_coding)
        {
          lang->language_range.start = coding_mark - buf;
          lang->language_range.length = p - coding_mark;
        }
        else if (prev_s == s_lang_coding_lws)
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
    case s_lang_coding:
      /* considered media-subtype completed */
      lang->language_range.start = coding_mark - buf;
      lang->language_range.length = p - coding_mark;
      break;
    case s_lang_coding_lws:
      break;

    default:
      *parse_error = PARSING_FAILED_STATE_UNHANDLED;
      break;
  }

  return p;
}

const char* AcceptLanguageHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  const char* p;
  const char ch = 0;
  //uint32_t cparam_count = 0;
  int parse_error = 0;

  if (buflen == 0)
  {
    /* Empty Accept-Language header is allowed */
    this->parsing_stat = PARSED_SUCCESSFULLY;
    this->num_accept_languages = 1;
    return buf;
  }
  //*parse_error = 0;
  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = buflen;
  this->rawdata._pos = pos;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    accept_language_t* lang = &this->accept_languages[this->num_accept_languages++];
    p = parse_language_range_part(buf, p - buf, buflen, lang, &parse_error);
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
        p = parse_param_part(buf, p - buf, buflen, &lang->params[0], MAX_NUM_PARAMS, &lang->num_params, &parse_error, 1);
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
std::string AcceptLanguageHeader::GetHeaderValue()
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
  for (int i = 0; i < this->num_accept_languages; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      sbuf.append(1, ',');
    }
    accept_language_t* lang = &this->accept_languages[i];

    /* check for mandatory parts if exist */
    if (!(this->rawdata._length) || !(lang->language_range.length))
    {
      return "";
    }

    size_t length = (size_t)this->rawdata._length;
    sbuf.reserve(length);
    sbuf.append((const char*)this->rawdata._data + lang->language_range.start, lang->language_range.length);
    for (int i = 0; i < lang->num_params; i++)
    {
      sbuf.append(1, ';');
      sbuf.append((const char*)this->rawdata._data + lang->params[i].type.start, lang->params[i].type.length);
      if (lang->params[i].value.length)
      {
        sbuf.append(1, '=');
        sbuf.append((const char*)this->rawdata._data + lang->params[i].value.start, lang->params[i].value.length);
      }
    }
  }
  return sbuf;
}

int AcceptLanguageHeader::GetHeaderValue(std::string& value)
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
  for (int i = 0; i < this->num_accept_languages; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      value.append(1, ',');
    }
    accept_language_t* lang = &this->accept_languages[i];

    /* check for mandatory parts if exist */
    if (!(this->rawdata._length) || !(lang->language_range.length))
    {
      value = "";
      return 1;
    }

    size_t length = (size_t)this->rawdata._length;
    value.reserve(length);
    value.append((const char*)this->rawdata._data + lang->language_range.start, lang->language_range.length);
    for (int i = 0; i < lang->num_params; i++)
    {
      value.append(1, ';');
      value.append((const char*)this->rawdata._data + lang->params[i].type.start, lang->params[i].type.length);
      if (lang->params[i].value.length)
      {
        value.append(1, '=');
        value.append((const char*)this->rawdata._data + lang->params[i].value.start, lang->params[i].value.length);
      }
    }
  }
  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int AcceptLanguageHeader::GetHeaderValue(RawData& value)
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

void AcceptLanguageHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Accept-Language Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }

  for (int i = 0; i < this->num_accept_languages; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      buf << ',';
    }
    accept_language_t* lang = &this->accept_languages[i];

    buf << "language-range : " << std::string((const char*)this->rawdata._data + lang->language_range.start, lang->language_range.length) << std::endl;

    if (lang->num_params)
    {
      buf << "---------- Parameters ----------\n";
      for (int i = 0; i < lang->num_params; i++)
      {
        buf << std::string((const char*)this->rawdata._data + lang->params[i].type.start, lang->params[i].type.length);
        if (lang->params[i].value.length)
        {
          buf << '=';
          buf << std::string((const char*)this->rawdata._data + lang->params[i].value.start, lang->params[i].value.length);
          buf << std::endl;
        }
      }
    }
    buf << "----------------\n";
    buf << "Accept-Language: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
    buf << "---------------------------------------\n";
  }
}

