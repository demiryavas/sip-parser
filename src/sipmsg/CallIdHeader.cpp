
#include "CallIdHeader.h"

/*
   The Call-ID header field uniquely identifies a particular invitation
   or all registrations of a particular client.  A single multimedia
   conference can give rise to several calls with different Call-IDs,
   for example, if a user invites a single individual several times to
   the same (long-running) conference.  Call-IDs are case-sensitive and
   are simply compared byte-by-byte.

   Use of cryptographically random identifiers (RFC 1750) in the
   generation of Call-IDs is RECOMMENDED.  Implementations MAY use the
   form "localid@host". 

   The compact form of the Call-ID header field is i.

   Example:
      Call-ID: f81d4fae-7dec-11d0-a765-00a0c91e6bf6@biloxi.com
      i:f81d4fae-7dec-11d0-a765-00a0c91e6bf6@192.0.2.4

   Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
   callid   =  word [ "@" word ]

   word        =  1*(alphanum / "-" / "." / "!" / "%" / "*" /
                  "_" / "+" / "`" / "'" / "~" /
                  "(" / ")" / "<" / ">" /
                  ":" / "\" / DQUOTE /
                  "/" / "[" / "]" / "?" /
                  "{" / "}" )
 */

enum cid_hdr_parsing_state
{
  s_hdr_dead = 1
  , s_hdr_spaces_before_value
  , s_hdr_localid
  , s_hdr_host_start
  , s_hdr_host
  , s_hdr_host_ws
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum cid_hdr_parsing_state parse_header_char(enum cid_hdr_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_hdr_spaces_before_value:
      if (IS_WORD(ch))
      {
        return s_hdr_localid;
      }
      break;

    case s_hdr_localid:
      if (ch == '@')
      {
        return s_hdr_host_start;
      }
      if (IS_WORD(ch))
      {
        return s_hdr_localid;
      }
      break;

    case s_hdr_host_start:
      if (IS_WORD(ch))
      {
        return s_hdr_host;
      }
      break;

    case s_hdr_host:
      if (IS_WORD(ch))
      {
        return s_hdr_host;
      }
      if (ch == ((ch == ' ') || (ch == '\t') || (ch == CR) || (ch == LF)))
      {
        return s_hdr_host_ws;
      }
      break;

    case s_hdr_host_ws:
      if ((ch == ' ') || (ch == '\t') || (ch == CR) || (ch == LF))
      {
        return s_hdr_host_ws;
      }
      break;
  }
  return s_hdr_dead;
}

const char* CallIdHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  enum cid_hdr_parsing_state s = s_hdr_spaces_before_value;
  enum cid_hdr_parsing_state prev_s = s_hdr_spaces_before_value;
  const char* localid_mark = NULL;
  const char* host_mark = NULL;

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

      case s_hdr_localid:
        if (prev_s == s_hdr_spaces_before_value)
        {
          localid_mark = p;
        }
        break;

      case s_hdr_host_start:
        this->localId.start = localid_mark - buf;
        this->localId.length = p - localid_mark;
        break;

      case s_hdr_host:
        if (prev_s == s_hdr_host_start)
        {
          host_mark = p;
        }
        break;

      case s_hdr_host_ws:
        if (prev_s == s_hdr_host)
        {
          this->host.start = host_mark - buf;
          this->host.length = p - host_mark;
        }
        break;
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the last state to complete the job */
  /* be pesimistic and set parsing success */
  this->parsing_stat = PARSED_SUCCESSFULLY;
  if (s == s_hdr_localid)
  {
    /* in the case of 'host' part is not included in Call-ID, parsing can 
       be ended in s_hdr_localid */
    this->localId.start = localid_mark - buf;
    this->localId.length = p - localid_mark;
    return p;
  }
  else if (s == s_hdr_host)
  {
    /* header parsing has been completed when parsing host part. */
    this->host.start = host_mark - buf;
    this->host.length = p - host_mark;
    return p;
  }
  else if (s == s_hdr_host_ws)
  {
    /* ended after collecting method */
    return p;
  }

  this->parsing_stat = PARSING_FAILED_STATE_UNHANDLED; /* Un-handled success state flow. */
  return p; /* TODO: Provide meaningful error to upper layer */
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string CallIdHeader::GetHeaderValue()
{
  if (!(this->rawdata._length) || !(this->localId.length))
  {
    return "";
  }
  size_t length = (size_t)this->localId.length + this->host.length + 1;
  std::string sbuf;
  sbuf.reserve(length);
  sbuf.append((const char*)this->rawdata._data + this->localId.start, this->localId.length);
  if (this->host.length > 0)
  {
    sbuf.append(1, '@');
    sbuf.append((const char*)this->rawdata._data + this->host.start, this->host.length);
  }

  return sbuf;
}

int CallIdHeader::GetHeaderValue(std::string& value)
{
  if (!(this->rawdata._length) || !(this->localId.length))
  {
    return 1;
  }
  size_t length = (size_t)this->localId.length + this->host.length + 1;
  value.reserve(length);
  value.append((const char*)this->rawdata._data + this->localId.start, this->localId.length);
  if (this->host.length > 0)
  {
    value.append(1, '@');
    value.append((const char*)this->rawdata._data + this->host.start, this->host.length);
  }

  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int CallIdHeader::GetHeaderValue(RawData& value)
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

void CallIdHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Call-ID Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  buf << "localid : " << std::string((const char*)this->rawdata._data + this->localId.start, this->localId.length) << std::endl;
  if (this->host.length)
  {
    buf << "host    : " << std::string((const char*)this->rawdata._data + this->host.start, this->host.length) << std::endl;
  }

  buf << "----------------\n";
  buf << "Call-ID: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}
