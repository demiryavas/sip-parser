/*
 * SipMessage.cpp
 *
 *  Created on: Apr 19, 2020
 *      Author: demir
 */

#include "SipMessage.h"
#include "Utility.h"

#include <iostream>
#include <sstream>
#include <iomanip>

#include <map>
#include <algorithm>

/* Utility function */
void SipMessage::PrintoutData(std::ostringstream &buff, unsigned char *data, unsigned int len)
{
  for (unsigned int i = 0; i<len; i++)
  {
    if ((i % 16) == 0)
      buff << '\n';
    else
      if ((i % 4) == 0)
        buff << ' ';

    buff << std::hex << std::setw(2) << std::setfill('0')
         << (unsigned int)(data[i] & 0xff);
  }
  buff << std::endl;
}

int SipMessage::GetRequestUrl(RawData& value)
{
  if (this->request_url.length > 0)
  {
    value._data = (unsigned char*)(&this->v1[this->request_url.start]);
    value._length = this->request_url.length;
  }
  else
  {
    value._data = NULL;
    value._length = 0;
  }

  return 0;
}

int SipMessage::GetHeaderCount(unsigned char* headerName)
{
  return GetHeaderCount(headerName, strlen((const char*)headerName));
}

int SipMessage::GetHeaderCount(unsigned char* headerName, uint32_t hnmlen)
{
  int count = 0;
  int result = 0;

  /* Try to count if the header has both short-form and long-form name definition */
  char* s_hname = NULL;
  uint32_t s_hnmlen = 0;
  char s_h;
  if (hnmlen == 1)
  {
    /* most probably short-form of header name is used, try to find headers in long-form */
    s_hname = (char*)GetLongHeaderName((const char)headerName[0]);
    if (s_hname != NULL)
    {
      s_hnmlen = strlen(s_hname);
    }
  }
  else
  {
    /* check for name in short-form */
    s_h = GetShortHeaderName((const char*)headerName);
    s_hname = (char *)&s_h;
    if (s_hname != NULL)
    {
      s_hnmlen = 1;
    }
  }

  for (int i = 0; i < this->num_headers; i++)
  {
    if (hnmlen == this->headers[i].fieldpos.length)
    {
      result = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)headerName, hnmlen);
      if (result == 0)
      {
        count++;
      }
    }
    else if ((s_hnmlen) && (s_hnmlen == this->headers[i].fieldpos.length))
    {
      result = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)s_hname, s_hnmlen);
      if (result == 0)
      {
        count++;
      }
    }
  }

  return count;
}

std::string SipMessage::GetHeaderValue(unsigned char* headerName, uint32_t idx)
{
  return GetHeaderValue(headerName, strlen((const char*)headerName), idx);
}

std::string SipMessage::GetHeaderValue(unsigned char* headerName, uint32_t hnmlen, uint32_t idx)
{
  int result = 0;
  int final = 0;
  char sname = 0;
  uint32_t count = 0;
recheck:
  for (int i = 0; i < this->num_headers; i++)
  {
    if (hnmlen == this->headers[i].fieldpos.length)
    {
      result = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)headerName, hnmlen);
      if (result == 0)
      {
        if (idx == count)
        {
          return std::string(&this->v1[this->headers[i].valuepos.start], this->headers[i].valuepos.length);
        }
        count++;
      }
    }
  }
  if (final) {
    return std::string();
  }
  /* No data found for the given 'headerName', check if the other form (short or long) is available and
    check it is included in that form in the message */
  if (hnmlen == 1) {
    /* It is in short-faorm, so there should be a representation in long-form */
    headerName = (unsigned char*)GetLongHeaderName((char)headerName[0]);
    if (headerName)
    {
      hnmlen = strlen((const char*)headerName);
      final = 1;
      goto recheck;
    }
  }
  else
  {
    sname = GetShortHeaderName((const char*)headerName);
    if (sname)
    {
      headerName = (unsigned char*)&sname;
      hnmlen = 1;
      final = 1;
      goto recheck;
    }
  }

  return std::string();
}

int SipMessage::GetHeaderValue(unsigned char* headerName, std::string& value, uint32_t idx)
{
  return GetHeaderValue(headerName, strlen((const char*)headerName), value, idx);
}

int SipMessage::GetHeaderValue(unsigned char* headerName, uint32_t hnmlen, std::string& value, uint32_t idx)
{
  int result = 0;
  int final = 0;
  char sname = 0;
  uint32_t count = 0;
recheck:
  for (int i = 0; i < this->num_headers; i++)
  {
    if (hnmlen == this->headers[i].fieldpos.length)
    {
      result = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)headerName, hnmlen);
      if (result == 0)
      {
        if (idx == count)
        {
          value.assign(&this->v1[this->headers[i].valuepos.start], this->headers[i].valuepos.length);
          return result;
        }
        count++;
      }
    }
  }
  if (final) {
    return result;
  }
  /* No data found for the given 'headerName', check if the other form (short or long) is available and
    check it is included in that form in the message */
  if (hnmlen == 1) {
    /* It is in short-faorm, so there should be a representation in long-form */
    headerName = (unsigned char*)GetLongHeaderName((char)headerName[0]);
    if (headerName)
    {
      hnmlen = strlen((const char*)headerName);
      final = 1;
      goto recheck;
    }
  }
  else
  {
    sname = GetShortHeaderName((const char*)headerName);
    if (sname)
    {
      headerName = (unsigned char*)&sname;
      hnmlen = 1;
      final = 1;
      goto recheck;
    }
  }

  return result;
}

int SipMessage::GetHeaderValue(unsigned char* headerName, RawData& value, uint32_t idx)
{
  return GetHeaderValue(headerName, strlen((const char*)headerName), value, idx);
}

int SipMessage::GetHeaderValue(unsigned char* headerName, uint32_t hnmlen, RawData& value, uint32_t idx)
{
  int result = 0;
  int final = 0;
  char sname = 0;
  uint32_t count = 0;
recheck:
  for (int i = 0; i < this->num_headers; i++)
  {
    if (hnmlen == this->headers[i].fieldpos.length)
    {
      result = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)headerName, hnmlen);
      if (result == 0)
      {
        if (idx == count)
        {
          //value.assign(&this->v1[this->headers[i].valuepos.start], this->headers[i].valuepos.length);
          value._data = (unsigned char*)(&this->v1[this->headers[i].valuepos.start]);
          value._length = this->headers[i].valuepos.length;
          return result;
        }
        count++;
      }
    }
  }
  if (final) {
    return result;
  }
  /* No data found for the given 'headerName', check if the other form (short or long) is available and
    check it is included in that form in the message */
  if (hnmlen == 1) {
    /* It is in short-faorm, so there should be a representation in long-form */
    headerName = (unsigned char*)GetLongHeaderName((char)headerName[0]);
    if (headerName)
    {
      hnmlen = strlen((const char*)headerName);
      final = 1;
      goto recheck;
    }
  }
  else
  {
    sname = GetShortHeaderName((const char*)headerName);
    if (sname)
    {
      headerName = (unsigned char*)&sname;
      hnmlen = 1;
      final = 1;
      goto recheck;
    }
  }

  return result;
}

int SipMessage::GetHeaderValuesInList(unsigned char* headerName, std::list<std::string>& strlist)
{
  return GetHeaderValuesInList(headerName, strlen((const char*)headerName), strlist);
}

int SipMessage::GetHeaderValuesInList(unsigned char* headerName, uint32_t hnmlen, std::list<std::string>& strlist)
{
  int result = 1;
  int final = 0;
  char sname = 0;
reexecute:
  for (int i = 0; i < this->num_headers; i++)
  {
    if (hnmlen == this->headers[i].fieldpos.length)
    {
      int ret = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)headerName, hnmlen);
      if (ret == 0)
      {
        strlist.push_back(std::string(&this->v1[this->headers[i].valuepos.start], this->headers[i].valuepos.length));
        result = 0; /* we have a matching at least */
      }
    }
  }
  if (final) {
    return result;
  }
  /* No data found for the given 'headerName', check if the other form (short or long) is available and
    check it is included in that form in the message */
  if (hnmlen == 1) {
    /* It is in short-faorm, so there should be a representation in long-form */
    headerName = (unsigned char*)GetLongHeaderName((char)headerName[0]);
    if (headerName)
    {
      hnmlen = strlen((const char*)headerName);
      final = 1;
      goto reexecute;
    }
  }
  else
  {
    sname = GetShortHeaderName((const char*)headerName);
    if (sname)
    {
      headerName = (unsigned char*)&sname;
      hnmlen = 1;
      final = 1;
      goto reexecute;
    }
  }
  return result;
}

int SipMessage::GetHeaderValuesInList(unsigned char* headerName, std::list<RawData>& rwdlist)
{
  return GetHeaderValuesInList(headerName, strlen((const char*)headerName), rwdlist);
}

int SipMessage::GetHeaderValuesInList(unsigned char* headerName, uint32_t hnmlen, std::list<RawData>& rwdlist)
{
  int result = 1;
  int final = 0;
  char sname = 0;
reexecute:
  for (int i = 0; i < this->num_headers; i++)
  {
    if (hnmlen == this->headers[i].fieldpos.length)
    {
      int ret = _strnicmp_(&this->v1[this->headers[i].fieldpos.start], (const char*)headerName, hnmlen);
      if (ret == 0)
      {
        rwdlist.push_back(RawData((unsigned char*)(&this->v1[this->headers[i].valuepos.start]), this->headers[i].valuepos.length));
        result = 0; /* we have a matching at least */
      }
    }
  }
  if (final) {
    return result;
  }
  /* No data found for the given 'headerName', check if the other form (short or long) is available and
    check it is included in that form in the message */
  if (hnmlen == 1) {
    /* It is in short-faorm, so there should be a representation in long-form */
    headerName = (unsigned char*)GetLongHeaderName((char)headerName[0]);
    if (headerName)
    {
      hnmlen = strlen((const char*)headerName);
      final = 1;
      goto reexecute;
    }
  }
  else
  {
    sname = GetShortHeaderName((const char*)headerName);
    if (sname)
    {
      headerName = (unsigned char*)&sname;
      hnmlen = 1;
      final = 1;
      goto reexecute;
    }
  }
  return result;
}

/*const*/ RawData* SipMessage::GetBody()
{
  return new RawData((unsigned char*)&this->v1[this->msg_body.start], this->msg_body.length);
}

int SipMessage::GetBody(RawData& rawData)
{
  rawData._data = (unsigned char*)&this->v1[this->msg_body.start];
  rawData._length = this->msg_body.length;

  return 0;
}

const char* SipMessage::GetLongHeaderName(char shName)
{
  /* mnemonics from https://www.cs.columbia.edu/sip/compact.html */
  switch (shName) 
  {
    case 'A':
    case 'a': return "Accept-Contact";
    case 'B':
    case 'b': return "Referred-By";     /* -refer- "by" */
    case 'C':
    case 'c': return "Content-Type";
    case 'D':
    case 'd': return "Request-Disposition";
    case 'E':
    case 'e': return "Content-Encoding";
    case 'F':
    case 'f': return "From";
    case 'I':
    case 'i': return "Call-ID";
    case 'J':
    case 'j': return "Reject-Contact";
    case 'K':
    case 'k': return "Supported";        /* "know" */
    case 'L':
    case 'l': return "Content-Length";
    case 'M':
    case 'm': return "Contact";          /* "moved" */
    case 'O':
    case 'o': return "Event";            /* -event- "occurence" */
    case 'R':
    case 'r': return "Refer-To";         /* -refer- */
    case 'S':
    case 's': return "Subject";
    case 'T':
    case 't': return "To";
    case 'U':
    case 'u': return "Allow-Events";     /* -events-	"understand" */
    case 'V':
    case 'v': return "Via";
    case 'X':
    case 'x': return "Session-Expires";
    case 'Y':
    case 'y': return "Identity";
  }
                                                 
  return NULL;
}

std::string str_tolower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 // static_cast<int(*)(int)>(std::tolower)         // wrong
                 // [](int c){ return std::tolower(c); }           // wrong
                 // [](char c){ return std::tolower(c); }          // wrong
                 [](unsigned char c) { return std::tolower(c); } // correct
  );
  return s;
}

const char SipMessage::GetShortHeaderName(const char* hdrName)
{
  static std::map<std::string, char> shNames = { {"accept-contact",      'a'},
                                                 {"referred-by",         'b'},
                                                 {"content-type",        'c'},
                                                 {"request-disposition", 'd'},
                                                 {"content-encoding",    'e'},
                                                 {"from",                'f'},
                                                 {"call-id",             'i'},
                                                 {"reject-contact",      'j'},
                                                 {"supported",           'k'},
                                                 {"content-length",      'l'},
                                                 {"contact",             'm'},
                                                 {"event",               'o'},
                                                 {"refer-to",            'r'},
                                                 {"subject",             's'},
                                                 {"to",                  't'},
                                                 {"allow-events",        'u'},
                                                 {"via",                 'v'},
                                                 {"session-expires",     'x'},
                                                 {"identity",            'y'}
                                               };

  std::string str(hdrName);
  str = str_tolower(str);
  std::map<std::string, char>::iterator it = shNames.find(str);
  if (it != shNames.end())
  {
    return it->second;
  }
  return 0;
}

void SipMessage::PrintOut(std::ostringstream &buf)
{
  unsigned char* rawdata = (unsigned char*)&this->v1[0];

  buf << "-------- SIP MESSAGE DUMP ----------\n";
  if (this->type == SIP_REQUEST)
  {
    std::string rurl((const char*)rawdata + this->request_url.start, this->request_url.length);
    buf << sip_method_str(this->method) << " "
        << std::string((const char*)rawdata + this->request_url.start, this->request_url.length) << " "
        << "SIP/" << this->sip_major << "." << this->sip_minor << "\r\n";
  }
  else
  {
    // response message
    buf << "SIP/" << this->sip_major << "." << this->sip_minor << ' '
        << this->status_code;
    if (this->response_status.length > 0)
    {
      buf << ' ' << std::string((const char*)rawdata + this->response_status.start, this->response_status.length);
    }
    buf << std::endl;
  }
  for (int i = 0; i < this->num_headers; i++)
  {
    buf << std::string((const char*)rawdata + this->headers[i].fieldpos.start, this->headers[i].fieldpos.length) << ": "
        << std::string((const char*)rawdata + this->headers[i].valuepos.start, this->headers[i].valuepos.length) << "\r\n";
  }
  buf << "_________ body _________\n";
  for (int i = this->msg_body.start; i < (this->msg_body.start + this->msg_body.length); i++)
  {
    buf << (char)rawdata[i];
  }
  buf << std::endl;
  buf << "_____ msg in hex ______\n";
  PrintoutData(buf, (unsigned char*)&v1[0], this->v1.size());
}

