/* The approach used here is inspired from HTTP parser given in
 * https://github.com/nodejs/http-parser from version 2.9.4
 *
 * At least in the beginning, we follow the same way to implement
 * a SIP parser for high performance
 */
#ifndef __SIP_PARSER_H__
#define __SIP_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Also update SONAME in the Makefile whenever you change these. */
#define SIP_PARSER_VERSION_MAJOR 1
#define SIP_PARSER_VERSION_MINOR 0
#define SIP_PARSER_VERSION_PATCH 0

#include <stddef.h>
#if defined(_WIN32) && !defined(__MINGW32__) && \
  (!defined(_MSC_VER) || _MSC_VER<1600) && !defined(__WINE__)
#include <BaseTsd.h>
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

/* Compile with -DSIP_PARSER_STRICT=0 to make less checks, but run
 * faster
 */
#ifndef SIP_PARSER_STRICT
# define SIP_PARSER_STRICT 0
#endif

/* Maximium header size allowed. If the macro is not defined
 * before including this header then the default is used. To
 * change the maximum header size, define the macro in the build
 * environment (e.g. -DSIP_MAX_HEADER_SIZE=<value>). To remove
 * the effective limit on the size of the header, define the macro
 * to a very large number (e.g. -DSIP_MAX_HEADER_SIZE=0x7fffffff)
 */
#ifndef SIP_MAX_HEADER_SIZE
# define SIP_MAX_HEADER_SIZE (80*1024)
#endif

typedef struct sip_parser sip_parser;
typedef struct sip_parser_settings sip_parser_settings;


/* Callbacks should return non-zero to indicate an error. The parser will
 * then halt execution.
 *
 * The one exception is on_headers_complete. In a SIP_RESPONSE parser
 * returning '1' from on_headers_complete will tell the parser that it
 * should not expect a body. This is used when receiving a response to a
 * HEAD request which may contain 'Content-Length' or 'Transfer-Encoding:
 * chunked' headers that indicate the presence of a body.
 *
 * Returning `2` from on_headers_complete will tell parser that it should not
 * expect neither a body nor any futher responses on this connection. This is
 * useful for handling responses to a CONNECT request which may not contain
 * `Upgrade` or `Connection: upgrade` headers.
 *
 * http_data_cb does not return data chunks. It will be called arbitrarily
 * many times for each string. E.G. you might get 10 callbacks for "on_url"
 * each providing just a few characters more data.
 */
typedef int (*sip_data_cb) (sip_parser*, const char *at, size_t length);
typedef int (*sip_cb) (sip_parser*);

/* https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml */
/* Status Codes */
#define SIP_STATUS_MAP(XX)                                                  \
  XX(100, TRYING,                          Trying)                          \
  XX(180, RINGING,                         Ringing)                         \
  XX(181, CALL_IS_BEING_FORWARDED,         Call is Being Forwarded)         \
  XX(182, QUEUED,                          Queued)                          \
  XX(183, SESSION_PROGRESS,                Session Progress)                \
  XX(199, EARLY_DIALOG_TERMINATED,         Early Dialog Terminated)         \
  XX(200, OK,                              OK)                              \
  XX(202, ACCEPTED,                        Accepted)                        \
  XX(204, NO_NOTIFICATION,                 No Notification)                 \
  XX(300, MULTIPLE_CHOICES,                Multiple Choices)                \
  XX(301, MOVED_PERMANENTLY,               Moved Permanently)               \
  XX(302, MOVED_TEMPORARILY,               Moved Temporarily)               \
  XX(305, USE_PROXY,                       Use Proxy)                       \
  XX(380, ALTERNATIVE_SERVICE,             Alternative Service)             \
  XX(400, BAD_REQUEST,                     Bad Request)                     \
  XX(401, UNAUTHORIZED,                    Unauthorized)                    \
  XX(402, PAYMENT_REQUIRED,                Payment Required)                \
  XX(403, FORBIDDEN,                       Forbidden)                       \
  XX(404, NOT_FOUND,                       Not Found)                       \
  XX(405, METHOD_NOT_ALLOWED,              Method Not Allowed)              \
  XX(406, NOT_ACCEPTABLE_406,              Not Acceptable)                  \
  XX(407, PROXY_AUTHENTICATION_REQUIRED,   Proxy Authentication Required)   \
  XX(408, REQUEST_TIMEOUT,                 Request Timeout)                 \
  XX(410, GONE,                            Gone)                            \
  XX(412, CONDITIONAL_REQUEST_FAILED,      Conditional Request Failed)      \
  XX(413, REQUEST_ENTITY_TOO_LARGE,        Request Entity Too Large)        \
  XX(414, REQUEST_URI_TOO_LARGE,           Request Entity Too Large)        \
  XX(415, UNSUPPORTED_MEDIA_TYPE,          Unsupported Media Type)          \
  XX(416, UNSUPPORTED_URI_SCHEME,          Unsupported URI Scheme)          \
  XX(417, UNKNOWN_RESOURCE_PRIORITY,       Unknown Resource-Priority)       \
  XX(420, BAD_EXTENSION,                   Bad Extension)                   \
  XX(421, EXTENSION_REQUIRED,              Extension Required)              \
  XX(422, SESSION_INTERVAL_TOO_SMALL,      Session Interval Too Small)      \
  XX(423, INTERVAL_TOO_BRIEF,              Interval Too Brief)              \
  XX(424, BAD_LOCATION_INFORMATION,        Bad Location Information)        \
  XX(425, BAD_ALERT_MESSAGE,               Bad Alert Message)               \
  XX(428, USE_IDENTITY_HEADER,             Use Identity Header)             \
  XX(429, PROVIDE_REFERRER_IDENTITY,       Provide Referrer Identity)       \
  XX(430, FLOW_FAILED,                     Flow failed)                     \
  XX(433, ANONYMITY_DISALLOWED,            Anonymity Disallowed)            \
  XX(436, BAD_IDENTITY_INFO,               Bad Identity Info)               \
  XX(437, UNSUPPORTED_CREDENTIAL,          Unsupported Credential)          \
  XX(438, INVALID_IDENTITY_HEADER,         Invalid Identity Header)         \
  XX(439, FIRST_HOP_LACKS_OUTBOUND_SUPPORT,First Hop Lacks Outbound Support)\
  XX(440, MAX_BREADTH_EXCEEDED,            Max-Breadth Exceeded)            \
  XX(469, BAD_INFO_PACKAGE,                Bad Info Package)                \
  XX(470, CONSENT_NEEDED,                  Consent Needed)                  \
  XX(480, TEMPORARILY_UNAVAILABLE,         Temporarily Unavailable)         \
  XX(481, CALL_TRANSACTION_DOES_NOT_EXIST, Call/Transaction Does Not Exist) \
  XX(482, LOOP_DETECTED,                   Loop Detected)                   \
  XX(483, TOO_MANY_HOPS,                   Too Many Hops)                   \
  XX(484, ADDRESS_INCOMPLETE,              Address Incomplete)              \
  XX(485, AMBIGUOUS,                       Ambiguous)                       \
  XX(486, BUSY_HERE,                       Busy Here)                       \
  XX(487, REQUEST_TERMINATED,              Request Terminated)              \
  XX(488, NOT_ACCEPTABLE_HERE,             Not Acceptable Here)             \
  XX(489, BAD_EVENT,                       Bad Event)                       \
  XX(491, REQUEST_PENDING,                 Request Pending)                 \
  XX(493, UNDECIPHERABLE,                  Undecipherable)                  \
  XX(494, SECURITY_AGREEMENT_REQUIRED,     Security Agreement Required)     \
  XX(500, INTERNAL_SERVER_ERROR,           Internal Server Error)           \
  XX(501, NOT_IMPLEMENTED,                 Not Implemented)                 \
  XX(502, BAD_GATEWAY,                     Bad Gateway)                     \
  XX(503, SERVICE_UNAVAILABLE,             Service Unavailable)             \
  XX(504, SERVER_TIMEOUT,                  Server Timeout)                  \
  XX(505, VERSION_NOT_SUPPORTED,           Version Not Supported)           \
  XX(513, MESSAGE_TOO_LARGE,               Message Too Large)               \
  XX(555, PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED, Push Notification Service Not Supported) \
  XX(580, PRECONDITION_FAILURE,            Precondition Failure)            \
  XX(600, BUSY_EVERYWHERE,                 Busy Everywhere)                 \
  XX(603, DECLINE,                         Decline)                         \
  XX(604, DOES_NOT_EXIST_ANYWHERE,         Does Not Exist Anywhere)         \
  XX(606, NOT_ACCEPTABLE_606,              Not Acceptable)                  \
  XX(607, UNWANTED,                        Unwanted)                        \
  XX(608, REJECTED,                        Rejected)                        \

enum sip_status
  {
#define XX(num, name, string) SIP_STATUS_##name = num,
  SIP_STATUS_MAP(XX)
#undef XX
  };

/* Request Methods */
#define SIP_METHOD_MAP(XX)          \
  XX(0,  ACK,          ACK)         \
  XX(1,  BYE,          BYE)         \
  XX(2,  CANCEL,       CANCEL)      \
  XX(3,  INFO,         INFO)        \
  XX(4,  INVITE,       INVITE)      \
  XX(5,  MESSAGE,      MESSAGE)     \
  XX(6,  NOTIFY,       NOTIFY)      \
  XX(7,  OPTIONS,      OPTIONS)     \
  XX(8,  PRACK,        PRACK)       \
  XX(9,  PUBLISH,      PUBLISH)     \
  XX(10, REFER,        REFER)       \
  XX(11, REGISTER,     REGISTER)    \
  XX(12, SUBSCRIBE,    SUBSCRIBE)   \
  XX(13, UPDATE,       UPDATE)      \

enum sip_method
  {
#define XX(num, name, string) SIP_##name = num,
  SIP_METHOD_MAP(XX)
#undef XX
  };


enum sip_parser_type { SIP_REQUEST, SIP_RESPONSE, SIP_BOTH };

/* The followings need to be updated for SIP */
#if 0
/* Flag values for http_parser.flags field */
enum flags
  { F_CHUNKED               = 1 << 0
  , F_CONNECTION_KEEP_ALIVE = 1 << 1
  , F_CONNECTION_CLOSE      = 1 << 2
  , F_CONNECTION_UPGRADE    = 1 << 3
  , F_TRAILING              = 1 << 4
  , F_UPGRADE               = 1 << 5
  , F_SKIPBODY              = 1 << 6
  , F_CONTENTLENGTH         = 1 << 7
  , F_TRANSFER_ENCODING     = 1 << 8  /* Never set in http_parser.flags */
  };
#endif

enum flags
  { F_CONTENTLENGTH               = 1 << 0
  , F_SKIPBODY                    = 1 << 1 /* Not sure be needed for SIP */
  };

/* TODO: Although almost all error messages are applicable for SIP
 * there may be a need to remove some and add some new ones
 */
/* Map for errno-related constants
 *
 * The provided argument should be a macro that takes 2 arguments.
 */
#define SIP_ERRNO_MAP(XX)                                            \
  /* No error */                                                     \
  XX(OK, "success")                                                  \
                                                                     \
  /* Callback-related errors */                                      \
  XX(CB_message_begin, "the on_message_begin callback failed")       \
  XX(CB_url, "the on_url callback failed")                           \
  XX(CB_header_field, "the on_header_field callback failed")         \
  XX(CB_header_value, "the on_header_value callback failed")         \
  XX(CB_headers_complete, "the on_headers_complete callback failed") \
  XX(CB_body, "the on_body callback failed")                         \
  XX(CB_message_complete, "the on_message_complete callback failed") \
  XX(CB_status, "the on_status callback failed")                     \
  XX(CB_chunk_header, "the on_chunk_header callback failed")         \
  XX(CB_chunk_complete, "the on_chunk_complete callback failed")     \
                                                                     \
  /* Parsing-related errors */                                       \
  XX(INVALID_EOF_STATE, "stream ended at an unexpected time")        \
  XX(HEADER_OVERFLOW,                                                \
     "too many header bytes seen; overflow detected")                \
  XX(CLOSED_CONNECTION,                                              \
     "data received after completed connection: close message")      \
  XX(INVALID_VERSION, "invalid HTTP version")                        \
  XX(INVALID_STATUS, "invalid HTTP status code")                     \
  XX(INVALID_METHOD, "invalid HTTP method")                          \
  XX(INVALID_URL, "invalid URL")                                     \
  XX(INVALID_HOST, "invalid host")                                   \
  XX(INVALID_PORT, "invalid port")                                   \
  XX(INVALID_PATH, "invalid path")                                   \
  XX(INVALID_QUERY_STRING, "invalid query string")                   \
  XX(INVALID_FRAGMENT, "invalid fragment")                           \
  XX(LF_EXPECTED, "LF character expected")                           \
  XX(INVALID_HEADER_TOKEN, "invalid character in header")            \
  XX(INVALID_CONTENT_LENGTH,                                         \
     "invalid character in content-length header")                   \
  XX(UNEXPECTED_CONTENT_LENGTH,                                      \
     "unexpected content-length header")                             \
  XX(INVALID_CHUNK_SIZE,                                             \
     "invalid character in chunk size header")                       \
  XX(INVALID_CONSTANT, "invalid constant string")                    \
  XX(INVALID_INTERNAL_STATE, "encountered unexpected internal state")\
  XX(STRICT, "strict mode assertion failed")                         \
  XX(PAUSED, "parser is paused")                                     \
  XX(UNKNOWN, "an unknown error occurred")                           \
  XX(INVALID_TRANSFER_ENCODING,                                      \
     "request has invalid transfer-encoding")                        \


/* Define SPE_* values for each errno value above */
#define SIP_ERRNO_GEN(n, s) SPE_##n,
enum sip_errno {
  SIP_ERRNO_MAP(SIP_ERRNO_GEN)
};
#undef SIP_ERRNO_GEN


/* Get an sip_errno value from an sip_parser */
#define SIP_PARSER_ERRNO(p)            ((enum sip_errno) (p)->sip_errno)


struct sip_parser {
  /** PRIVATE **/
  unsigned int type : 2;         /* enum http_parser_type */
  unsigned int flags : 8;        /* F_* values from 'flags' enum; semi-public */
  unsigned int state : 7;        /* enum state from http_parser.c */
  unsigned int header_state : 7; /* enum header_state from sipparser.c */
  unsigned int index : 5;        /* index into current matcher */
  unsigned int extra_flags : 2;
  unsigned int lenient_http_headers : 1;

  uint32_t nread;          /* # bytes read in various scenarios */
  uint64_t content_length; /* # bytes in body (0 if no Content-Length header) */

  /** READ-ONLY **/
  unsigned short sip_major;
  unsigned short sip_minor;
  unsigned int status_code : 16; /* responses only */
  unsigned int method : 8;       /* requests only */
  unsigned int sip_errno : 7;

  /* TODO: Upgrade is not applicable for SIP. It is to be removed after boundary check of this struct */
  /* 1 = Upgrade header was present and the parser has exited because of that.
   * 0 = No upgrade header present.
   * Should be checked when sip_parser_execute() returns in addition to
   * error checking.
   */
  unsigned int upgrade : 1;

  void *data; /* A pointer to get hook to the "connection" or "socket" object */
};


struct sip_parser_settings {
  sip_cb      on_message_begin;
  sip_data_cb on_url;
  sip_data_cb on_status;
  sip_data_cb on_header_field;
  sip_data_cb on_header_value;
  sip_cb      on_headers_complete;
  sip_data_cb on_body;
  sip_cb      on_message_complete;
  /* TODO: Chunk is not applicable for SIP. To be removed after deciding the design strategy
   * for multipart body support
   */
  /* When on_chunk_header is called, the current chunk length is stored
   * in parser->content_length.
   */
  sip_cb      on_chunk_header;
  sip_cb      on_chunk_complete;
};

/* TODO: We are planning to support SIP URI parsing separately. */
#if 0
enum http_parser_url_fields
  { UF_SCHEMA           = 0
  , UF_HOST             = 1
  , UF_PORT             = 2
  , UF_PATH             = 3
  , UF_QUERY            = 4
  , UF_FRAGMENT         = 5
  , UF_USERINFO         = 6
  , UF_MAX              = 7
  };


/* Result structure for http_parser_parse_url().
 *
 * Callers should index into field_data[] with UF_* values iff field_set
 * has the relevant (1 << UF_*) bit set. As a courtesy to clients (and
 * because we probably have padding left over), we convert any port to
 * a uint16_t.
 */
struct http_parser_url {
  uint16_t field_set;           /* Bitmask of (1 << UF_*) values */
  uint16_t port;                /* Converted UF_PORT string */

  struct {
    uint16_t off;               /* Offset into buffer in which field starts */
    uint16_t len;               /* Length of run in buffer */
  } field_data[UF_MAX];
};
#endif

/* Returns the library version. Bits 16-23 contain the major version number,
 * bits 8-15 the minor version number and bits 0-7 the patch level.
 * Usage example:
 *
 *   unsigned long version = http_parser_version();
 *   unsigned major = (version >> 16) & 255;
 *   unsigned minor = (version >> 8) & 255;
 *   unsigned patch = version & 255;
 *   printf("sip_parser v%u.%u.%u\n", major, minor, patch);
 */
unsigned long sip_parser_version(void);

void sip_parser_init(sip_parser *parser, enum sip_parser_type type);


/* Initialize sip_parser_settings members to 0
 */
void sip_parser_settings_init(sip_parser_settings *settings);


/* Executes the parser. Returns number of parsed bytes. Sets
 * `parser->sip_errno` on error. */
size_t sip_parser_execute(sip_parser *parser,
                           const sip_parser_settings *settings,
                           const char *data,
                           size_t len);

/* TODO: Think about necessity */

/* If http_should_keep_alive() in the on_headers_complete or
 * on_message_complete callback returns 0, then this should be
 * the last message on the connection.
 * If you are the server, respond with the "Connection: close" header.
 * If you are the client, close the connection.
 */
int sip_should_keep_alive(const sip_parser *parser);

/* Returns a string version of the SIP method. */
const char *sip_method_str(enum sip_method m);

/* Returns a string version of the SIP status code. */
const char *sip_status_str(enum sip_status s);

/* Return a string name of the given error */
const char *sip_errno_name(enum sip_errno err);

/* Return a string description of the given error */
const char *sip_errno_description(enum sip_errno err);

/* TODO: Think about necessity */
#if 0
/* Initialize all sip_parser_url members to 0 */
void sip_parser_url_init(struct sip_parser_url *u);

/* Parse a URL; return nonzero on failure */
int sip_parser_parse_url(const char *buf, size_t buflen,
                         int is_connect,
                         struct sip_parser_url *u);
#endif

/* Pause or un-pause the parser; a nonzero value pauses */
void sip_parser_pause(sip_parser *parser, int paused);

/* Checks if this is the final chunk of the body. */
int sip_body_is_final(const sip_parser *parser);

/* Change the maximum header size provided at compile time. */
void sip_parser_set_max_header_size(uint32_t size);

#ifdef __cplusplus
}
#endif
#endif

