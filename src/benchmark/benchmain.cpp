#include <osipparser2/internal.h>
#include <osipparser2/osip_port.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/sdp_message.h>

#include "sipparser.h"
#include "SipMessage.h"
#include "SipUri.h"
#include "CSeqHeader.h"
#include "CallIdHeader.h"
#include "ViaHeader.h"
#include "FromHeader.h"
#include "ToHeader.h"
#include "SubjectHeader.h"
#include "ContentTypeHeader.h"

#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#include <iostream>
#include <sstream>

unsigned long mhash(const char* str)
{
  unsigned int hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;

  return hash & 0xFFFFFFFFu;
}

/* Although used header names may include non-alpha characters, like '-',
   we consider same logic will be applied both set and received values,
   then there will be no problem to find the relation */
#define LOWERC(c)  (unsigned char)(c | 0x20)

/* 'constexpr' is important here to use the function in a swithc-case mechanism */
constexpr unsigned long nhash(const char* str)
{
  unsigned int hash = 5381;
  int c = 0;

  while ((c = *str++))
    //hash = ((hash << 5) + hash) + c;
    hash = ((hash << 5) + hash) + LOWERC(c);

  return hash & 0xFFFFFFFFu;
}

/* modified version well-known hash function to support length information
   i.e. no C-ended string case */
unsigned long lhash(const char* str, int len)
{
  unsigned int hash = 5381;
  int c;

  while ((c = *str++) && (len--))
    hash = ((hash << 5) + hash) + LOWERC(c);

  return hash & 0xFFFFFFFFu;
}

SipHeader* CreateSipHeader(const char* hname, int len)
{
  switch (lhash(hname, len))
  {
  case nhash("Via"):
    return new ViaHeader();

  case nhash("From"):
    return new FromHeader();

  case nhash("To"):
    return new ToHeader();

  case nhash("Call-ID"):
    return new CallIdHeader();

  case nhash("CSeq"):
    return new CSeqHeader();

  case nhash("Subject"):
    return new SubjectHeader();

  case nhash("Content-Type"):
    return new ContentTypeHeader();

  default:
    return NULL;
  }
}


/* Message handler callback to be invoked when a complete message received during parsing */
void HandleReceivedMessage(SipMessage* msg)
{
#ifdef VERBOSE_TEST
  /* As tester behavior, save the received message into the list */
  std::cout << "\n............................. <HANDLE RECEIVED MESSAGE> ......................\n";
  std::ostringstream buff;
  msg->PrintOut(buff);
  std::cout << buff.str() << std::endl;
  std::cout << "\n............................. >HANDLE RECEIVED MESSAGE< ......................\n";
#endif
  /* Parse headers to provide same functionality of osip parser for a fair compare */
  for (int i = 0; i < msg->num_headers; i++)
  {
    SipHeader* hdr = CreateSipHeader(&msg->v1[msg->headers[i].fieldpos.start], msg->headers[i].fieldpos.length);
    if (hdr)
    {
      hdr->ParseHeader(&msg->v1[msg->headers[i].valuepos.start], 0, msg->headers[i].valuepos.length);
    }
  }
}

int on_message_begin(sip_parser* p) {
#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* Message BEGIN ******************\n";
  buff << "Method: " << p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;
  sipmsg->message_begin_cb_called = 1;
  /* when parsing data consists of two messages, 'bias' determine the actual position */
  sipmsg->message_begin_pos = (*p->position) - p->parsing_data + sipmsg->bias;

#ifdef SIP_DETAILED_DEBUG
  std::cout << "Message begin POS: " << sipmsg->message_begin_pos << std::endl;
#endif

  sipmsg->type = (sip_parser_type)p->type;
#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif

  return 0;
}

int on_url(sip_parser* p, const char* at, size_t length) {
#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* REQUEST URL ******************\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << (uint32_t)p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
  buff << "Received chars\n";

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;

  for (size_t i = 0; i < length; i++)
  {
    buff << at[i];
  }
  buff << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;
  /* keep current-parse position same with parser's position */
  if (sipmsg->request_url.start == 0)
  {
    sipmsg->request_url.start = (at - p->parsing_data) + sipmsg->bias;
  }
  sipmsg->request_url.length += length;

  /* Message is a request message and 'method' information shall be
   * determined at this step
   */
  sipmsg->method = (sip_method)p->method;

#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif
  return 0;
}

int on_response_status(sip_parser* p, const char* buf, size_t len)
{
#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* RESPONSE STATUS ******************\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
  std::cout << buff.str();
#endif
  SipMessage* sipmsg = (SipMessage*)p->currmsg;
  /* keep current-parse position same with parser's position */
  if (sipmsg->response_status.start == 0)
  {
    sipmsg->response_status.start = (buf - p->parsing_data) + sipmsg->bias;
  }
  sipmsg->response_status.length += len;
  sipmsg->status_cb_called = 1;

#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif
  return 0;
}

int on_header_field(sip_parser* p, const char* at, size_t length) {

#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* HEADER FIELD ******************\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
  buff << "Received chars\n";

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;

  for (size_t i = 0; i < length; i++)
  {
    if (at[i] == ' ')
      buff << '.';
    else
      buff << at[i];
  }
  buff << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;
  if (sipmsg->num_headers == 0)
  {
    /* first header encountered, which means also we have
     * sip version info at parser
     */
    sipmsg->sip_major = p->sip_major;
    sipmsg->sip_minor = p->sip_minor;
  }
  if (sipmsg->last_header_element != FIELD)
  {
    sipmsg->num_headers++;
  }

  if (sipmsg->headers[sipmsg->num_headers - 1].fieldpos.start == 0)
  {
    sipmsg->headers[sipmsg->num_headers - 1].fieldpos.start = (at - p->parsing_data) + sipmsg->bias;
  }
#if SIP_PARSER_STRICT
  sipmsg->headers[sipmsg->num_headers - 1].fieldpos.length += length;
#else
  sipmsg->headers[sipmsg->num_headers - 1].fieldpos.length += length;
  /* we need to eliminate spaces between header-name and ":" */
  while (*(at + sipmsg->headers[sipmsg->num_headers - 1].fieldpos.length - 1) == ' ')
  {
    sipmsg->headers[sipmsg->num_headers - 1].fieldpos.length--;
  }
#endif

  sipmsg->last_header_element = FIELD;

#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif

  return 0;
}

int on_header_value(sip_parser* p, const char* at, size_t length) {

#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* HEADER VALUE ******************\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
  buff << "Received chars\n";
#endif
  /* when the 'data' of parser is completed but message needs more data from
     network for completion, the 'position' of parser may point out of the
     data, so may need correction */
  unsigned char* corrPos = (unsigned char*)*p->position;
  if (corrPos >= (unsigned char*)(p->parsing_data + p->parsing_len))
  {
    corrPos--;
  }
#ifdef SIP_DETAILED_DEBUG
  buff << "Current position=" << std::hex << (uint64_t)*p->position
    << " corrected position=" << std::hex << (uint64_t)corrPos << std::dec << std::endl;

  for (size_t i = 0; i < length; i++)
  {
    buff << at[i];
  }
  buff << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;

  /* keep current-parse position same with parser's position */
  bool possibleFolding = true;

  if (sipmsg->headers[sipmsg->num_headers - 1].valuepos.start == 0)
  {
    sipmsg->headers[sipmsg->num_headers - 1].valuepos.start = (at - p->parsing_data) + sipmsg->bias;
    possibleFolding = false;
  }
  /* in the case of folding, parser skips spaces in the new line before providing
     header value; so, we need to take it into account to keep data position in data space. */
  if (possibleFolding)
  {
    char* hstart = &sipmsg->v1[0];

    uint32_t tlen = (at - (hstart + sipmsg->headers[sipmsg->num_headers - 1].valuepos.start +
                           sipmsg->headers[sipmsg->num_headers - 1].valuepos.length));
    sipmsg->headers[sipmsg->num_headers - 1].valuepos.length += tlen;
  }
  sipmsg->headers[sipmsg->num_headers - 1].valuepos.length += length;

  sipmsg->last_header_element = VALUE;

#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif

  return 0;
}

int on_headers_complete(sip_parser* p) {
#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* HEADERS COMPLETE ******************\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;
  sipmsg->method = (sip_method)p->method;
  sipmsg->status_code = p->status_code;
  sipmsg->sip_major = p->sip_major;
  sipmsg->sip_minor = p->sip_minor;
  sipmsg->headers_complete_cb_called = 1 /*TRUE*/;

  /* keep current-parse position same with parser's position */
  sipmsg->headers_complete_pos = (*p->position - p->parsing_data) + sipmsg->bias;
  sipmsg->should_keep_alive = sip_should_keep_alive(p);

#ifdef SIP_DETAILED_DEBUG
  std::cout << "Headers complete POS: " << sipmsg->headers_complete_pos << std::endl;
  std::cout << "---------------------------------------------------------\n";
#endif

  return 0;
}

int on_message_complete(sip_parser* p) {
#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* MESSAGE COMPLETE ******************\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;

  /* keep current-parse position same with parser's position */
  sipmsg->message_complete_cb_called = 1;
  sipmsg->message_complete_pos = (*p->position - p->parsing_data) + sipmsg->bias;

  const char* new_data = (*p->position) + 1;
  if (new_data < p->parsing_data + p->parsing_len)
  {
    p->currmsg = new SipMessage();
    const char* nptr = new_data;
    char ch;
    /* Set raw data  if remaining in the buffer */
    for (nptr = new_data; nptr != p->parsing_data + p->parsing_len; nptr++)
    {
      ch = *nptr;
      ((SipMessage*)p->currmsg)->v1.push_back(ch);
    }
    /* Bias will be negative value */
    ((SipMessage*)p->currmsg)->bias = p->parsing_data - new_data;
  }
  else
  {
    p->currmsg = NULL;
  }

  /* call message-handler for a received complete SIP message */
  HandleReceivedMessage(sipmsg);

#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif

  return 0;
}

int on_body(sip_parser* p, const char* at, size_t length) {
#ifdef SIP_DETAILED_DEBUG
  std::ostringstream buff;
  buff << "************* ---- BODY ---- ******************\n";
  buff << "body_cb callback is called with settings:\n";
  buff << "Method: " << (uint32_t)p->method << std::endl;
  buff << "Type: " << (uint32_t)p->type << std::endl;
  buff << "Flags: " << (uint32_t)p->flags << std::endl;
  buff << "State: " << (uint32_t)p->state << std::endl;
  buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
  buff << "Index: " << (uint32_t)p->index << std::endl;
  buff << "Nread: " << p->nread << std::endl;
  buff << "Content-Length: " << p->content_length << std::endl;
  buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
  buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
  buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
  buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
  buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
  buff << "Received chars\n";

  buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;

  for (size_t i = 0; i < length; i++)
  {
    buff << at[i];
  }
  buff << std::endl;
  std::cout << buff.str();
#endif

  SipMessage* sipmsg = (SipMessage*)p->currmsg;

  if (sipmsg->msg_body.start == 0)
  {
    sipmsg->msg_body.start = (at - p->parsing_data) + sipmsg->bias;
  }
  sipmsg->msg_body.length += length;

  sipmsg->body_is_final = sip_body_is_final(p);

#ifdef SIP_DETAILED_DEBUG
  std::cout << "---------------------------------------------------------\n";
#endif

  return 0;
}

int read_message(char* filename, char** msg, int *msglen)
{
  long file_length = 0;
  //char* data = NULL;

  FILE* file = fopen(filename, "rb");  /* (DY) for text read cases Windows resplaces CRLF pairs with LF.
                                          This causes parsing failures especially for inconsistence on (text) body length */
  if (file == NULL) 
  {
    perror("fopen");
    //fclose(file);
    return -1;
  }

  fseek(file, 0, SEEK_END);
  file_length = ftell(file);
  if (file_length == -1) 
  {
    perror("ftell");
    fclose(file);
    return -2;
  }
  fseek(file, 0, SEEK_SET);

  *msg = (char*)malloc(file_length);
  if (fread(*msg, 1, file_length, file) != (size_t)file_length) 
  {
    fprintf(stderr, "couldn't read entire file\n");
    free(msg);
    *msg = NULL;
    fclose(file);
    return -3;
  }
  *msglen = file_length;
  return 0;
}

int test_osip(char* msg, int msglen, int loopcount)
{
  osip_message_t* sip;
  int err = 0;
  char* result;

  int j = loopcount;

  fprintf(stdout, "Trying %i sequentials calls to osip_message_init(), osip_message_parse() and osip_message_free()\n", j);
  while (j != 0) 
  {
    j--;
    osip_message_init(&sip);
    err = osip_message_parse(sip, msg, msglen);
    if (err != 0) 
    {
      fprintf(stdout, "ERROR: failed while parsing!\n");
      osip_message_free(sip);
      return err;
    }
    osip_message_free(sip);
  }

  return 0;
}

int test_sip(sip_parser* parser, const sip_parser_settings* settings, char* msg, int msglen, int loopcount)
{
  size_t nparsed = 0;
  SipMessage* currentmsg = NULL;

  int j = loopcount;
  fprintf(stdout, "Trying %i sequentials calls to new SipMessage(), sip_parser_execute() and delete SipMessage instance\n", j);
  
  while (j != 0)
  {
    j--;
    currentmsg = new SipMessage();
    currentmsg->v1.resize(msglen);
    memcpy(&currentmsg->v1[0], msg, msglen);

    parser->currmsg = currentmsg;

    nparsed = sip_parser_execute(parser, settings, msg, msglen);
    //free(msg);
    delete currentmsg;

    if (nparsed != (size_t)msglen)
    {
      fprintf(stderr,
              "Error: %s (%s)\n",
              sip_errno_description(SIP_PARSER_ERRNO(parser)),
              sip_errno_name(SIP_PARSER_ERRNO(parser)));
      return -1;
    }
  }
  free(msg);
  return 0;
}

#define FILE_NAME "../../src/osiptest/res/sip12x3"
#define LOOP_COUNT 1000000

//#define OSIP_TEST

int main(int argc, char* argv[]) 
{
  int result = 0;
  char* filename = (char*)FILE_NAME;
  char* msg = NULL;
  int msglen = 0;

  if (argc >= 2) 
  {
    filename = argv[1];
  }
  unsigned long h1 = nhash("Via");
  unsigned long h2 = lhash("Via:", 3);
  unsigned long h3 = mhash("via");

  std::cout << "h1=" << h1 << "\nh2=" << h2 << "\nh3=" << h3 << std::endl;

  unsigned long h11 = nhash("Content-Type");
  unsigned long h21 = lhash("Content-Type:", 12);
  unsigned long h31 = mhash("Content-Type");

  std::cout << "h1=" << h11 << "\nh2=" << h21 << "\nh3=" << h31 << std::endl;

  result = read_message(filename, &msg, &msglen);
  if (result != 0)
  {
    return result;
  }

#ifdef OSIP_TEST
  /* initialize parser */
  parser_init();
#else
  sip_parser_settings settings;
  memset(&settings, 0, sizeof(settings));
  settings.on_message_begin = on_message_begin;
  settings.on_url = on_url;
  settings.on_status = on_response_status;
  settings.on_header_field = on_header_field;
  settings.on_header_value = on_header_value;
  settings.on_headers_complete = on_headers_complete;
  settings.on_body = on_body;
  settings.on_message_complete = on_message_complete;

  sip_parser parser;
  sip_parser_init(&parser, SIP_BOTH);
#endif

  clock_t begin = clock();

#ifdef OSIP_TEST
  test_osip(msg, msglen, LOOP_COUNT);
#else
  test_sip(&parser, &settings, msg, msglen, LOOP_COUNT);
#endif

  clock_t end = clock();

  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

  printf("Spent time: %f\n", time_spent);

  return EXIT_SUCCESS;
}
