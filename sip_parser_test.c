#include "sipparser.h"

#include <assert.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_HEADERS 64
#define MAX_ELEMENT_SIZE 2048
//#define MAX_CHUNKS 16

#ifdef __cplusplus
extern "C" {
#endif

struct message 
{
  const char* name; // for debugging purposes
  const char* raw;
  enum sip_parser_type type;
  enum sip_method method;
  int status_code;
  char response_status[MAX_ELEMENT_SIZE];
  char request_path[MAX_ELEMENT_SIZE];
  char request_url[MAX_ELEMENT_SIZE];
  char fragment[MAX_ELEMENT_SIZE];
  char query_string[MAX_ELEMENT_SIZE];
  char body[MAX_ELEMENT_SIZE];
  size_t body_size;
  const char* host;
  const char* userinfo;
  uint16_t port;
  int num_headers;
  enum { NONE = 0, FIELD, VALUE } last_header_element;
  char headers[MAX_HEADERS][2][MAX_ELEMENT_SIZE];

  unsigned short sip_major;
  unsigned short sip_minor;
  uint64_t content_length;

  int message_begin_cb_called;
  int headers_complete_cb_called;
  int message_complete_cb_called;
  int status_cb_called;
  int message_complete_on_eof;
  int body_is_final;
  int allow_chunked_length;
};

static sip_parser test_parser;
sip_parser_settings settings;

static struct message messages[5];
static int num_messages;

static int currently_parsing_eof;

size_t strlncat(char* dst, size_t len, const char* src, size_t n)
{
  size_t slen;
  size_t dlen;
  size_t rlen;
  size_t ncpy;

  slen = strnlen(src, n);
  dlen = strnlen(dst, len);

  if (dlen < len) 
  {
    rlen = len - dlen;
    ncpy = slen < rlen ? slen : (rlen - 1);
    memcpy(dst + dlen, src, ncpy);
    dst[dlen + ncpy] = '\0';
  }

  assert(len > slen + dlen);
  return slen + dlen;
}

void check_body_is_final(const sip_parser* p)
{
  if (messages[num_messages].body_is_final) {
    fprintf(stderr, "\n\n *** Error sip_body_is_final() should return 1 "
            "on last on_body callback call "
            "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }
  messages[num_messages].body_is_final = sip_body_is_final(p);
}


int on_message_begin(sip_parser* p) 
{
  assert(p == &test_parser);
  assert(!messages[num_messages].message_begin_cb_called);
  messages[num_messages].message_begin_cb_called = 1;
  printf("-------------- on-message-begin ---------------------\n");
  return 0;
}

int on_url(sip_parser* p, const char* at, size_t length) 
{
  assert(p == &test_parser);
  strlncat(messages[num_messages].request_url,
           sizeof(messages[num_messages].request_url),
           at,
           length);
  printf("-------------- on-url ---------------------: %.*s\n", (int)length, at);
  return 0;
}

int on_response_status(sip_parser* p, const char* buf, size_t len)
{
  assert(p == &test_parser);

  messages[num_messages].status_cb_called = 1;

  strlncat(messages[num_messages].response_status,
           sizeof(messages[num_messages].response_status),
           buf,
           len);
  printf("-------------- on-response-status ---------------------: %.*s\n", (int)len, buf);
  return 0;
}

int on_header_field(sip_parser* p, const char* at, size_t length) 
{
  assert(p == &test_parser);
  struct message* m = &messages[num_messages];

  if (m->last_header_element != FIELD)
  {
    m->num_headers++;
  }
  strlncat(m->headers[m->num_headers - 1][0],
           sizeof(m->headers[m->num_headers - 1][0]),
           at,
           length);

  m->last_header_element = FIELD;
  printf("-------------- on-header-field ---------------------: %.*s\n", (int)length, at);
  return 0;
}

int on_header_value(sip_parser* p, const char* at, size_t length) 
{
  assert(p == &test_parser);
  struct message* m = &messages[num_messages];

  strlncat(m->headers[m->num_headers - 1][1],
           sizeof(m->headers[m->num_headers - 1][1]),
           at,
           length);

  m->last_header_element = VALUE;
  printf("-------------- on-header-value ---------------------: %.*s\n", (int)length, at);
  return 0;
}

int on_headers_complete(sip_parser* p) 
{
  assert(p == &test_parser);
  messages[num_messages].method = test_parser.method;
  messages[num_messages].status_code = test_parser.status_code;
  messages[num_messages].sip_major = test_parser.sip_major;
  messages[num_messages].sip_minor = test_parser.sip_minor;
  messages[num_messages].content_length = test_parser.content_length;
  messages[num_messages].headers_complete_cb_called = 1;
  printf("-------------- on-headers-complete ---------------------\n");
  return 0;
}

int on_message_complete(sip_parser* p) 
{
  assert(p == &test_parser);
  if (messages[num_messages].body_size &&
      !messages[num_messages].body_is_final)
  {
    fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
            "on last on_body callback call "
            "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }

  messages[num_messages].message_complete_cb_called = 1;

  messages[num_messages].message_complete_on_eof = currently_parsing_eof;

  num_messages++;
  printf("-------------- on-message-complete ---------------------\n");
  return 0;
}


int on_body(sip_parser* p, const char* at, size_t length) 
{
  assert(p == &test_parser);
  strlncat(messages[num_messages].body,
           sizeof(messages[num_messages].body),
           at,
           length);
  messages[num_messages].body_size += length;
  check_body_is_final(p);
  printf("-------------- on-body ---------------------: %.*s\n", (int)length, at);
  return 0;
}

void usage(const char* name) 
{
  fprintf(stderr,
          "Usage: %s $filename [-t (type) r/b/q] [-p (process) s/d] \n"
          "    where 'type' can be one of {r,b,q}\n"
          "          parses message as a Response, reQuest, or Both\n"
          "    where 'process' can be one of {s,d}\n"
          "          's' is for streamed messages, 'd' is for datagram\n",
          name);
  exit(EXIT_FAILURE);
}

char* temp_data = { "INVITE sip:watson@boston.bell-tel.com SIP/2.0\r\n"
                   "Via: SIP/2.0/UDP first.example.com:4000;branch=z9hG4bKa7c6a8dlze.1\r\n"
                   "Via: SIP/2.0/UDP kton.bell-tel.com\r\n"
                   "From: A.Bell <sip:a.g.bell@bell-tel.com>;tag=3\r\n"
                   "To: T.Watson <sip:watson@bell-tel.com>\r\n"
                   "Call-ID: 662606876@kton.bell-tel.com\r\n"
                   "CSeq: 1 INVITE\r\n"
                   "Subject: Mr.Watson, come here.\r\n"
                   "Content-Type: application/sdp;\r\n"
                   "  micalg=sha1;boundary=boundary42\r\n"
                   "Content-Length: 237\r\n"
                   "\r\n"
                   "v=0\r\n"
                   "o=bell 53655765 2353687637 IN IP4 128.3.4.5\r\n"
                   "s=Mr. Watson, come here.\r\n"
                   "t=3149328600 0\r\n"
                   "c=IN IP4 kton.bell-tel.com\r\n"
                   "m=audio 3456 RTP/AVP 0 3 4 5\r\n"
                   "a=rtpmap:0 PCMU/8000\r\n"
                   "a=rtpmap:3 GSM/8000\r\n"
                   "a=rtpmap:4 G723/8000\r\n"
                   "a=rtpmap:5 DVI4/8000\r\n"
};

int main(int argc, char* argv[])
{
  enum sip_parser_type file_type = SIP_BOTH;
  size_t nparsed = 0;
  char* data = temp_data;
  long msg_length = strlen(data);
  int pos = 0;
  int processing_type = 0; /* 0 : datagram, 1 : streaming */
  int data_from_file = 0;

  pos = 2;
  while (pos < argc)
  {
    printf("%s\n", argv[pos]);
    if (0 == strncmp(argv[pos], "-t", 2))
    {
      pos++;
      char ch = argv[pos][0];
      switch (ch)
      {
        case 'r':
          file_type = SIP_RESPONSE;
          break;

        case 'q':
          file_type = SIP_REQUEST;
          break;

        case 'b':
          file_type = SIP_BOTH;
          break;

        default:
          usage(argv[0]);
      }
    }
    else if (0 == strncmp(argv[pos], "-p", 2))
    {
      pos++;
      char ch = argv[pos][0];
      switch (ch)
      {
        case 's':
          processing_type = 1;
          break;

        case 'q':
          processing_type = 0;
          break;

        default:
          usage(argv[0]);
      }
    }
    pos++;
  }

  if (argc > 1) {
    char* filename = argv[1];
    FILE* file = fopen(filename, "rb");
    if (file == NULL)
    {
      perror("fopen");
      fclose(file);
      return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    msg_length = ftell(file);
    if (msg_length == -1)
    {
      perror("ftell");
      fclose(file);
      return EXIT_FAILURE;
    }
    fseek(file, 0, SEEK_SET);

    data = (char*)malloc(msg_length);
    if (fread(data, 1, msg_length, file) != (size_t)msg_length)
    {
      fprintf(stderr, "couldn't read entire file\n");
      free(data);
      fclose(file);
      return EXIT_FAILURE;
    }
    fclose(file);
    data_from_file = 1;
  }

  printf("Parsing data with length=%lu, file-type=%d, processing-type=%d\n", 
         msg_length, file_type, processing_type);

  memset(&settings, 0, sizeof(settings));
  settings.on_message_begin = on_message_begin;
  settings.on_url = on_url;
  settings.on_status = on_response_status;
  settings.on_header_field = on_header_field;
  settings.on_header_value = on_header_value;
  settings.on_headers_complete = on_headers_complete;
  settings.on_body = on_body;
  settings.on_message_complete = on_message_complete;

  test_parser.data = NULL;
  sip_parser_init(&test_parser, SIP_BOTH);

  nparsed = 0;
  nparsed = sip_parser_execute(&test_parser, &settings, data, msg_length);
  if (((long)nparsed != msg_length) || (test_parser.sip_errno != SPE_OK))
  {
    fprintf(stderr, "MessageReceived: Someting wrong with parsing, received msg-length=%lu while %lu of them is parsed! Error-No:%d-%s-%s\n",
            msg_length, nparsed, test_parser.sip_errno,
            sip_errno_name((enum sip_errno)test_parser.sip_errno),
            sip_errno_description((enum sip_errno)test_parser.sip_errno));
    test_parser.sip_errno = SPE_OK;
  }

  if (data_from_file) {
    free(data);
  }

  if (nparsed != (size_t)msg_length) 
  {
    fprintf(stderr, "Error: %s (%s)\n",
            sip_errno_description(SIP_PARSER_ERRNO(&test_parser)),
            sip_errno_name(SIP_PARSER_ERRNO(&test_parser)));
    return EXIT_FAILURE;
  }


  return EXIT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
