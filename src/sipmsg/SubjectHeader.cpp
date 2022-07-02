#include "SubjectHeader.h"

/*
   The Subject header field provides a summary or indicates the nature
   of the call, allowing call filtering without having to parse the
   session description.  The session description does not have to use
   the same subject indication as the invitation.

   The compact form of the Subject header field is s.

   Example:

      Subject: Need more boxes
      s: Tech Support

   Subject  =  ( "Subject" / "s" ) HCOLON [TEXT-UTF8-TRIM]

   The TEXT-UTF8 rule is only used for descriptive field contents and
   values that are not intended to be interpreted by the message parser.
   Words of *TEXT-UTF8 contain characters from the UTF-8 charset (RFC
   2279).  The TEXT-UTF8-TRIM rule is used for descriptive field
   contents that are n t quoted strings, where leading and trailing LWS
   is not meaningful.  In this regard, SIP differs from HTTP, which uses
   the ISO 8859-1 character set.

      TEXT-UTF8-TRIM  =  1*TEXT-UTF8char *(*LWS TEXT-UTF8char)
      TEXT-UTF8char   =  %x21-7E / UTF8-NONASCII
      UTF8-NONASCII   =  %xC0-DF 1UTF8-CONT
                      /  %xE0-EF 2UTF8-CONT
                      /  %xF0-F7 3UTF8-CONT
                      /  %xF8-Fb 4UTF8-CONT
                      /  %xFC-FD 5UTF8-CONT
      UTF8-CONT       =  %x80-BF

   A CRLF is allowed in the definition of TEXT-UTF8-TRIM only as part of
   a header field continuation.  It is expected that the folding LWS
   will be replaced with a single SP before interpretation of the TEXT-
   UTF8-TRIM value.
 */

#define TEXT_UTF8_CHAR(c)     ((c) >= 0x21 && (c) <= 0x7e)
#define UTF8_CONT(c)          ((c) >= 0x80 && (c) <= 0xbf)
#define UTF8_CONT_1(c)        ((c) >= 0xc0 && (c) <= 0xdf)
#define UTF8_CONT_2(c)        ((c) >= 0xe0 && (c) <= 0xef)
#define UTF8_CONT_3(c)        ((c) >= 0xf0 && (c) <= 0xf7)
#define UTF8_CONT_4(c)        ((c) >= 0xf8 && (c) <= 0xfb)
#define UTF8_CONT_5(c)        ((c) >= 0xfc && (c) <= 0xfd)
#define UTF8_NONASCII(c)      (UTF8_CONT(c) || UTF8_CONT_1(c) || UTF8_CONT_2(c) || \
                               UTF8_CONT_3(c) || UTF8_CONT_4(c) || UTF8_CONT_5(c))
#define TEXT_UTF8_TRIM(c)     (TEXT_UTF8_CHAR(c) || UTF8_NONASCII(c) || IS_LWS(c))

/* might be better to check not allowed ones */
#define NON_TEXT_UTF8_CHAR(c) ((c) < 0x20 || (c) == 0x7f || (c) > 0xfd)
enum subj_hdr_parsing_state   
{
    s_hdr_dead = 1
  , s_hdr_spaces_before_value
  , s_hdr_subject
  , s_hdr_subject_cr
  , s_hdr_subject_lf
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum subj_hdr_parsing_state parse_header_char(enum subj_hdr_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_hdr_spaces_before_value:
      /* Normally TEXT_UTF8_TRIM maco consists of LWS chars. But as depending of the state
         we may skip LSW chars at the beginning if there are */
      if (IS_LWS(ch))
      {
        return s;
      }
      else if (TEXT_UTF8_TRIM(ch))
      {
        return s_hdr_subject;
      }
      break;

    case s_hdr_subject:
      if (TEXT_UTF8_TRIM(ch))
      {
        /* TODO: Use unlikely */
        if (ch == CR)
        {
          return s_hdr_subject_cr;
        }
        return s_hdr_subject;
      }
      break;

    case s_hdr_subject_cr:
      if (ch == LF)
      {
        return s_hdr_subject_lf;
      }
      break;

    case s_hdr_subject_lf:
      /* we try to skip spaces used for folding indication, which are needed to 
         provide after a CRLF */
      if ((ch == ' ') || (ch == '\t'))
      {
        return s;
      }
      else if (TEXT_UTF8_TRIM(ch))
      {
        return s_hdr_subject;
      }
      /* otherwise it is an unexpected char/situation */
      break;

  }
  return s_hdr_dead;
}

const char* SubjectHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  enum subj_hdr_parsing_state s = s_hdr_spaces_before_value;
  enum subj_hdr_parsing_state prev_s = s_hdr_spaces_before_value;
  const char* subject_mark = NULL;
  const char* subject_part_mark = NULL;
  str_pos_t* curr_fold_part = &this->fold_parts[this->num_fold_parts++];
  
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

      case s_hdr_spaces_before_value:
        /* Nothing to do */
        break;

      case s_hdr_subject:
        if (prev_s == s_hdr_spaces_before_value)
        {
          subject_mark = p;
          subject_part_mark = p;
        }
        else if (prev_s == s_hdr_subject_lf)
        {
          /* new part has started (with skipped folding spaces) */
          curr_fold_part = &this->fold_parts[this->num_fold_parts++];
          subject_part_mark = p;
        }
        break;

      case s_hdr_subject_cr:
        if (prev_s == s_hdr_subject)
        {
          curr_fold_part->start = subject_part_mark - buf;
          curr_fold_part->length = p - subject_part_mark;
        }
        break;

      case s_hdr_subject_lf:
        /* nothing to do */
        break;
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the last state to complete the job */
  if (s == s_hdr_subject)
  {
    this->subject.start = subject_mark - buf;
    this->subject.length = p - subject_mark;

    curr_fold_part->start = subject_part_mark - buf;
    curr_fold_part->length = p - subject_part_mark;

    this->parsing_stat = PARSED_SUCCESSFULLY;
    return p;
  }

  this->parsing_stat = PARSING_FAILED_STATE_UNHANDLED;
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string SubjectHeader::GetHeaderValue()
{
  if (!(this->rawdata._length) || !(this->subject.length))
  {
    return "";
  }
  size_t length = (size_t)this->subject.length + 1;
  std::string sbuf;
  sbuf.reserve(length);
  for (int i = 0; i < this->num_fold_parts; i++)
  {
    if (i > 0)
    {
      sbuf.append(" ");
    }
    sbuf.append((const char*)this->rawdata._data + this->fold_parts[i].start, this->fold_parts[i].length);
  }

  return sbuf;
}

int SubjectHeader::GetHeaderValue(std::string& value)
{
  if (!(this->rawdata._length) || !(this->subject.length))
  {
    return 1;
  }
  size_t length = (size_t)this->subject.length + 1;
  value.reserve(length);
  for (int i = 0; i < this->num_fold_parts; i++)
  {
    if (i > 0)
    {
      value.append(" ");
    }
    value.append((const char*)this->rawdata._data + this->fold_parts[i].start, this->fold_parts[i].length);
  }

  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int SubjectHeader::GetHeaderValue(RawData& value)
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

void SubjectHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Subject Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }
  buf << "------- Folded Parts --------\n";
  for (int i = 0; i < this->num_fold_parts; i++)
  {
    buf << '[' << i << "]: " << std::string((const char*)this->rawdata._data + this->fold_parts[i].start, this->fold_parts[i].length) << std::endl;
  }
  buf << " ----------------\n";
  buf << "subject : " << std::string((const char*)this->rawdata._data + this->subject.start, this->subject.length) << std::endl;

  buf << "----------------\n";
  buf << "Subject: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}
