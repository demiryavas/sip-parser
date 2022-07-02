#include "FromHeader.h"
#include "Utility.h"
/*
   The From header field indicates the initiator of the request.  This
   may be different from the initiator of the dialog.  Requests sent by
   the callee to the caller use the callee's address in the From header
   field.

   The optional "display-name" is meant to be rendered by a human user
   interface.  A system SHOULD use the display name "Anonymous" if the
   identity of the client is to remain hidden.  Even if the "display-
   name" is empty, the "name-addr" form MUST be used if the "addr-spec"
   contains a comma, question mark, or semicolon.

   When the header field value contains a display name, the URI
   including all URI parameters is enclosed in "<" and ">".  If no "<"
   and ">" are present, all parameters after the URI are header
   parameters, not URI parameters.  The display name can be tokens, or a
   quoted string, if a larger character set is desired.

   Even if the "display-name" is empty, the "name-addr" form MUST be
   used if the "addr-spec" contains a comma, semicolon, or question
   mark.  There may or may not be LWS between the display-name and the
   "<".

   The compact form of the From header field is f.

   Examples:
      From: "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
      From: sip:+12125551212@server.phone2net.com;tag=887s
      f: Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8

   From           =  ( "From" / "f" ) HCOLON from-spec
   from-spec      =  ( name-addr / addr-spec ) *( SEMI from-param )
   name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
   addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
   display-name   =  *(token LWS)/ quoted-string
   from-param     =  tag-param / generic-param
   tag-param      =  "tag" EQUAL token
   generic-param  =  token [ EQUAL gen-value ]
   gen-value      =  token / host / quoted-string
   quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE
   qdtext         =  LWS / %x21 / %x23-5B / %x5D-7E / UTF8-NONASCII
                     ; Starting from '!' as excluding '"' and '\'
   The backslash character ("\") MAY be used as a single-character
   quoting mechanism only within quoted-string and comment constructs.
   Unlike HTTP/1.1, the characters CR and LF cannot be escaped by this
   mechanism to avoid conflict with line folding and header separation.

   quoted-pair    =  "\" (%x00-09 / %x0B-0C / %x0E-7F)
                     ; excluding LF and CR
 */

enum from_hdr_parsing_state
{ s_hdr_dead = 1
  , s_hdr_spaces_before_value
  , s_hdr_display_name
  , s_hdr_display_name_lws
  , s_hdr_display_name_quoted
  , s_hdr_display_name_quoted_end
  , s_hdr_display_name_quoted_end_lws
  , s_hdr_url_start
  , s_hdr_url_collect
  , s_hdr_url_collect_lws
  , s_hdr_url_start_with_laquot
  , s_hdr_url_collect_aquoted
  , s_hdr_url_with_angle_quot
  , s_hdr_url_end_with_raquot
  , s_hdr_url_end_with_raquot_lws
  , s_hdr_param_start
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum from_hdr_parsing_state parse_header_char(enum from_hdr_parsing_state s, const char ch, int* escaping)
{
  switch (s)
  {
    case s_hdr_spaces_before_value:
      /* We consider all LWS has been skipped */
      if (ch == '"')
      {
        return s_hdr_display_name_quoted;
      }
      if (ch == '<')
      {
        return s_hdr_url_start_with_laquot;
      }
      if (IS_TOKEN(ch))
      {
        return s_hdr_display_name;
      }
      if (IS_LWS(ch))
      {
        return s;
      }
      break;

    case s_hdr_display_name:
      if (IS_TOKEN(ch))
      {
        return s_hdr_display_name;
      }
      if (IS_LWS(ch))
      {
        return s_hdr_display_name_lws;
      }
      if (ch == '<')
      {
        return s_hdr_url_start_with_laquot;
      }
      if ((ch == ':') || (ch == '/'))
      {
        /* Special case: no display name is included and URL part is not angle-quoted */
        return s_hdr_url_start;
      }
      break;

    case s_hdr_url_start:
      /* TODO: url-parser is needed to be invoked. There may be a need to skip LWS chars */
      return s_hdr_url_collect; // !!
      break;

    case s_hdr_url_collect:
      /* TODO: url-parser is needed to be invoked. There may be a need to skip LWS chars */
      if (IS_LWS(ch))
      {
        return s_hdr_url_collect_lws;
      }
      if (ch == ';')
      {
        return s_hdr_param_start;
      }
      return s_hdr_url_collect; // !!
      break;

    case s_hdr_url_collect_lws:
      /* TODO: The logic here is not correct. There is a need to apply url-parser logic */
      if (IS_LWS(ch))
      {
        return s_hdr_url_collect_lws;
      }
      if (ch == ';')
      {
        return s_hdr_param_start;
      }
      /* Any other char. For now we are collecting anyway. Try to suuport LWS during URL */
      return s_hdr_url_collect; // !!
      break;

    case s_hdr_display_name_lws:
      if (IS_LWS(ch))
      {
        return s;
      }
      if (ch == '<')
      {
        return s_hdr_url_start_with_laquot;
      }
      if (IS_TOKEN(ch))
      {
        /* Display name has spaces, so continue */
        return s_hdr_display_name;
      }
      break;

    case s_hdr_display_name_quoted:
      if (ch == '"')
      {
        if (*escaping > 0)
        {
          /* we have an escaped '"' char in display-name */
          *escaping = 0;
          return s;
        }
        return s_hdr_display_name_quoted_end;
      }
      if (ch == '\\')
      {
        if (*escaping > 0)
        {
          /* we have an escaped '\' char in display-name */
          *escaping = 0;
        }
        else
        {
          *escaping = 1;
        }
        return s;
      }
      else
      {
        if ((ch != 0x0a) && (ch != 0x0d))
        {
          /* a char other than '\', '\r' and '\n', so collected a char even if escaped */
          *escaping = 0;
          return s;
        }
      }
      break;

    case s_hdr_display_name_quoted_end:
    case s_hdr_display_name_quoted_end_lws:
      if (IS_LWS(ch))
      {
        return s_hdr_display_name_quoted_end_lws;
      }
      if (ch == '<')
      {
        return s_hdr_url_start_with_laquot;
      }
      break;

    case s_hdr_url_start_with_laquot:
      /* TODO: We will collect all as an url until right-angle quote.
               Normally url-parser is needed to be invoked
               There may be a need to skip LWS chars */
      if (ch != '>')
      {
        return s_hdr_url_collect_aquoted;
      }
      break;

    case s_hdr_url_collect_aquoted:
      /* TODO: url-parser is needed to be invoked. There may be a need to skip LWS chars */
      if (ch == '>')
      {
        return s_hdr_url_end_with_raquot;
      }
      return s;
      break;

    case s_hdr_url_end_with_raquot:
    case s_hdr_url_end_with_raquot_lws:
      if (IS_LWS(ch))
      {
        return s_hdr_url_end_with_raquot_lws;
      }
      if (ch == ';')
      {
        return s_hdr_param_start;
      }
      break;

  }
  return s_hdr_dead;
}

 /* Parsing utility */
const char* FromHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  ParsingStatus_t result = PARSED_SUCCESSFULLY; /* be optimistic */
  enum from_hdr_parsing_state s = s_hdr_spaces_before_value;
  enum from_hdr_parsing_state prev_s = s_hdr_spaces_before_value;
  const char* dispname_mark = NULL;
  const char* url_mark = NULL;
  const char* param_name_mark = NULL;
  const char* param_value_mark = NULL;
  param_pos_t* current_param = NULL;

  int parse_error = 0;
  bool re_parse = false;
  int escaping = 0;
  const char* p;

  if (buflen == 0)
  {
    this->parsing_stat = PARSING_FAILED_NO_DATA;
    return buf;
  }

  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = buflen;
  this->rawdata._pos = pos;

reparse:

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_header_char(s, *p, &escaping);

    switch (s)
    {
      case s_hdr_display_name:
      case s_hdr_display_name_quoted:
        if (prev_s == s_hdr_spaces_before_value)
        {
          dispname_mark = p;
        }
        break;

      case s_hdr_display_name_lws:
        if (prev_s == s_hdr_display_name)
        {
          /* we may hit this position few times if display-name consists of spaces.
             The last hit will determine the actual display-name information*/
          this->displayName.start = dispname_mark - buf;
          this->displayName.length = p - dispname_mark;
        }
        break;

      case s_hdr_display_name_quoted_end_lws:
        if (prev_s == s_hdr_display_name_quoted_end)
        {
          this->displayName.start = dispname_mark - buf;
          this->displayName.length = p - dispname_mark;
        }
        break;

      case s_hdr_url_start:
        if (prev_s == s_hdr_display_name)
        {
          /* no display-name but URL without angle-quoted */
          re_parse = true;
          dispname_mark = NULL;
          prev_s = s_hdr_url_start;
          goto reparse;
        }
        break;

      case s_hdr_url_collect:
        if (prev_s == s_hdr_url_start)
        {
          url_mark = p;
        }
        break;

      case s_hdr_url_collect_lws:
        if (prev_s == s_hdr_url_collect)
        {
          this->url_str.start = url_mark - buf;
          this->url_str.length = p - url_mark;
        }
        break;

      case s_hdr_url_start_with_laquot:
        if ((prev_s == s_hdr_display_name) || (prev_s == s_hdr_display_name_quoted_end))
        {
          this->displayName.start = dispname_mark - buf;
          this->displayName.length = p - dispname_mark;
        }
        url_mark = p;
        break;

      case s_hdr_url_end_with_raquot_lws:
        if (prev_s == s_hdr_url_end_with_raquot)
        {
          this->url_str.start = url_mark - buf;
          this->url_str.length = p - url_mark;
        }
        break;

      case s_hdr_param_start:
        if (prev_s == s_hdr_url_end_with_raquot)
        {
          this->url_str.start = url_mark - buf;
          this->url_str.length = p - url_mark;
        }

        p++; // skip ';'
        p = parse_param_part(buf, p - buf, buflen, &this->params[0], MAX_NUM_PARAMS, &this->num_params, &parse_error, 0);
        if (parse_error)
        {
          /* TODO: Map parse_error to parsing_stat */
          this->parsing_stat = PARSING_FAILED_UNCLEAR_REASON;
          return p;
        }
        //printf("Number of parameters = %u and pos = %s", this->num_params, p);
        break;

      case s_hdr_dead:
        this->parsing_stat = PARSING_FAILED_STATE_DEAD;
        return p;
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the current state to complete the job */
  switch (s)
  {
    case s_hdr_url_end_with_raquot:
    case s_hdr_url_collect:
      this->url_str.start = url_mark - buf;
      this->url_str.length = p - url_mark;
      break;

    case s_hdr_url_end_with_raquot_lws:
    case s_hdr_url_collect_lws:
      /* Nothing to set */
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

/* parses URI part of From header if main parsing is done. */
int FromHeader::ParseUrlPart()
{
  if ((this->rawdata._data == NULL) || (this->rawdata._length == 0))
  {
    return 1;
  }
  if (this->url_str.length == 0)
  {
    return 2;
  }
  if (this->url)
  {
    /* Consider it has already been parsed */
    return 0;
  }
  this->url = new SipUri();
  if (*(this->rawdata._data + this->url_str.start) == '<')
  {
    /* addr-spec encapsulated with '<' and '>' */
    return this->url->ParseUri((const char*)this->rawdata._data + this->url_str.start + 1, 0, this->url_str.length - 2);
  }
  return this->url->ParseUri((const char*)this->rawdata._data + this->url_str.start, 0, this->url_str.length);
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string FromHeader::GetHeaderValue()
{
  /* check for mandatory parts if exist */
  if (!(this->rawdata._length) || !(this->url_str.length))
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
  if (this->displayName.length)
  {
    sbuf.append((const char*)this->rawdata._data + this->displayName.start, this->displayName.length);
    sbuf.append(1, ' ');
  }
  sbuf.append((const char*)this->rawdata._data + this->url_str.start, this->url_str.length);

  for (uint32_t i = 0; i < this->num_params; i++)
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

int FromHeader::GetHeaderValue(std::string& value)
{
  /* check for mandatory parts if exist */
  if (!(this->rawdata._length) || !(this->url_str.length))
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
  if (this->displayName.length)
  {
    value.append((const char*)this->rawdata._data + this->displayName.start, this->displayName.length);
    value.append(1, ' ');
  }
  value.append((const char*)this->rawdata._data + this->url_str.start, this->url_str.length);

  for (uint32_t i = 0; i < this->num_params; i++)
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
int FromHeader::GetHeaderValue(RawData& value)
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

void FromHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- " << this->hdrName << " Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }
  buf << "display-name : " << std::string((const char*)this->rawdata._data + this->displayName.start, this->displayName.length) << std::endl;
  buf << "url          : " << std::string((const char*)this->rawdata._data + this->url_str.start, this->url_str.length) << std::endl;

  if (this->num_params)
  {
    buf << "---------- Parameters ----------\n";
    for (uint32_t i = 0; i < this->num_params; i++)
    {
      buf << std::string((const char*)this->rawdata._data + this->params[i].type.start, this->params[i].type.length);
      if (this->params[i].value.length)
      {
        buf << '=';
        buf << std::string((const char*)this->rawdata._data + this->params[i].value.start, this->params[i].value.length);
      }
      buf << std::endl;
    }
  }
  if (this->url)
  {
    buf << "......Detailed URI.......\n";
    this->url->PrintOut(buf);
  }
  buf << "----------------\n";
  buf << this->hdrName << ": " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}