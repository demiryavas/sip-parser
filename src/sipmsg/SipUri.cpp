/*
 * SipUri.cpp
 *
 *  Created on: Apr 19, 2020
 *      Author: demir
 */

#include "SipUri.h"
#include "SipHeader.h"  /* to access macros */

/* General form of SIP URI:
   sip:user:password@host:port;uri-parameters?headers 
 
   BNF:
   SIP-URI  =  "sip:" [userinfo] hostport uri-parameters [headers]
   SIPS-URI  = "sips:" [userinfo] hostport uri-parameters [headers]
   userinfo = (user/telephone-subscriber) [":" password] "@"
   user = 1*(unreserved/escaped/user-unreserved)
   user-unreserved = "&"/" = "/"+"/"$"/","/";"/"?"/"/" 
   password  =  *(unreserved/escaped/"&"/" = "/"+"/"$"/",")
   hostport  =  host [":" port]
   host  =  hostname/IPv4address/IPv6reference
   hostname  =  *(domainlabel ".") toplabel ["."]
   domainlabel  =  alphanum /alphanum *(alphanum/"-") alphanum
   toplabel  =  ALPHA/ALPHA *(alphanum/"-") alphanum
   IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
   IPv6reference  =  "[" IPv6address "]"
   IPv6address    =  hexpart [ ":" IPv4address ]
   hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
   hexseq         =  hex4 *( ":" hex4)
   hex4           =  1*4HEXDIG
   port           =  1*DIGIT

   The BNF for telephone-subscriber can be found in RFC 2806.  Note,
   however, that any characters allowed there that are not allowed in
   the user part of the SIP URI MUST be escaped.

   uri-parameters    =  *( ";" uri-parameter)
   uri-parameter     =  transport-param / user-param / method-param
                        / ttl-param / maddr-param / lr-param / other-param
   transport-param   =  "transport=" ( "udp" / "tcp" / "sctp" / "tls" / other-transport)
   other-transport   =  token
   user-param        =  "user=" ( "phone" / "ip" / other-user)
   other-user        =  token
   method-param      =  "method=" Method
   ttl-param         =  "ttl=" ttl
   maddr-param       =  "maddr=" host
   lr-param          =  "lr"
   other-param       =  pname [ "=" pvalue ]
   pname             =  1*paramchar
   pvalue            =  1*paramchar
   paramchar         =  param-unreserved / unreserved / escaped
   param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"

   headers         =  "?" header *( "&" header )
   header          =  hname "=" hvalue
   hname           =  1*( hnv-unreserved / unreserved / escaped )
   hvalue          =  *( hnv-unreserved / unreserved / escaped )
   hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"

   token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
                  / "_" / "+" / "`" / "'" / "~" )

   Examples:
   sip:alice@atlanta.com
   sip:alice:secretword@atlanta.com;transport=tcp
   sips:alice@atlanta.com?subject=project%20x&priority=urgent
   sip:+1-212-555-1212:1234@gateway.com;user=phone
   sips:1212@gateway.com
   sip:alice@192.0.2.4
   sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com
   sip:alice;day=tuesday@atlanta.com

   The last sample URI above has a user field value of
   "alice;day=tuesday".  The escaping rules defined above allow a
   semicolon to appear unescaped in this field.  For the purposes of
   this protocol, the field is opaque.  The structure of that value is
   only useful to the SIP element responsible for the resource.
 */

/* This function is borrowed from osip */
 /* this method search for the separator and   */
 /* return it only if it is located before the */
 /* second separator. */
const char* next_separator(const char* ch, int separator_osip_to_find, int before_separator)
{
  const char* ind;
  const char* tmp;

  ind = strchr(ch, separator_osip_to_find);
  if (ind == NULL)
    return NULL;

  tmp = NULL;
  if (before_separator != 0)
    tmp = strchr(ch, before_separator);

  if (tmp != NULL) {
    if (ind < tmp)
      return ind;
  }
  else
    return ind;

  return NULL;
}

#if 0
/* Based on osip_uri_parse but no memory creation */
int SipUri::ParseUri(const char* buf, size_t length)
{
  const char* tmp = NULL;
  const char* host = NULL;
  const char* username = NULL;
  const char* password = NULL;
  const char* headers = NULL;
  const char* params = NULL;
  const char* port = NULL;

  size_t pos = 0;

  /* basic tests */
  if (buf == NULL || buf[0] == '\0')
     return 1; //OSIP_BADPARAMETER;
  /* (1) we prefer to go one by one
   * (2) TODO: use memchr if necessary
   */

  tmp = (char*)::memchr(buf, ':', length);
  if ((tmp == NULL) || (tmp - buf < 2))
  {
    return 2; // OSIP_SYNTAXERROR;
  }
//  if (tmp - buf < 2)
//    return 2; // OSIP_SYNTAXERROR;
  
  /* TODO: Think about if checking to see scheme part for being alpha is necessary */
/*
  i = 0;
  while (buf + i < tmp) {
    if (!osip_is_alpha(buf[i]))
      return OSIP_SYNTAXERROR;
    i++;
  }
*/

/*
  url->scheme = (char*)osip_malloc(tmp - buf + 1);
  if (url->scheme == NULL)
    return OSIP_NOMEM;
  osip_strncpy(url->scheme, buf, tmp - buf);
*/
  this->scheme.start = pos; // buf[0];
  this->scheme.length = tmp - buf;
  /* TODO: Not sure the following check is needed */
/*
  if (strchr(url->scheme, ' ') != NULL) {
    return OSIP_SYNTAXERROR;
  }
*/

  /* TODO: May be used a generic URI parsing logic as based on registered handlers */
#if 0
  if (strlen(url->scheme) < 3 || (0 != osip_strncasecmp(url->scheme, "sip", 3)
    && 0 != osip_strncasecmp(url->scheme, "sips", 4))) {        /* Is not a sipurl ! */
    size_t i = strlen(tmp + 1);

    if (i < 2)
      return OSIP_SYNTAXERROR;
    url->string = (char*)osip_malloc(i + 1);
    if (url->string == NULL)
      return OSIP_NOMEM;
    osip_strncpy(url->string, tmp + 1, i);
    return OSIP_SUCCESS;
  }
#endif

  /*  law number 1:
     if ('?' exists && is_located_after '@')
     or   if ('?' exists && '@' is not there -no username-)
     =====>  HEADER_PARAM EXIST
     =====>  start at index(?)
     =====>  end at the end of url
   */

  /* TODO: Not sure the following is ready */
#if 0
  /* find the beginning of host */
  username = strchr(buf, ':');
  /* if ':' does not exist, the url is not valid */
  if (username == NULL)
    return OSIP_SYNTAXERROR;
#endif
  username = tmp;

  //host = strchr(buf, '@');
  /* TODO: Recalculate the actual "length" */
  host = (char*)::memchr(buf, '@', length);
  if (host == NULL)
  {
    host = username;
  }
  else if (username[1] == '@')  /* username is empty */
  {
    host = username + 1;
  }
  else
    /* username exists */
  {
    password = next_separator(username + 1, ':', '@');
    if (password == NULL)
    {
      password = host;
    }
    else
      /* password exists */
    {
      if (host - password < 2)
      {
        return 2; // OSIP_SYNTAXERROR;
      }
      /*
      url->password = (char*)osip_malloc(host - password);
      if (url->password == NULL)
        return OSIP_NOMEM;
      osip_strncpy(url->password, password + 1, host - password - 1);
      */
      this->password.start = (password - &buf[0]) + 1;
      this->password.length = host - password - 1;

      /* TODO: This unscape replacement may be executed during creation of
               a copy for upper layer. An utility may also be created for upper layer */
      //__osip_uri_unescape(url->password);
    }
    if (password - username < 2)
    {
      return 2; // OSIP_SYNTAXERROR;
    }

    //{
    /*
      url->username = (char*)osip_malloc(password - username);
      if (url->username == NULL)
        return OSIP_NOMEM;
      osip_strncpy(url->username, username + 1, password - username - 1);
    */
    this->username.start = (username - &buf[0]) + 1;
    this->username.length = password - username - 1;
    /* TODO: This unscape replacement may be executed during creation of
               a copy for upper layer. An utility may also be created for upper layer */
    //  __osip_uri_unescape(url->username);
    //}

    /* search for header after host */
    //headers = strchr(host, '?');
    /* TODO: Recalculate the actual "length" */
    headers = (char*)::memchr(host, '?', length);
/*    if (headers == NULL)
    {
      headers = buf + strlen(buf);
    }
    else*/
    if (headers != NULL)
    {
      /* headers exist */
      ParseUriHeaders(headers, length - (headers - buf));
    }
  }

  /* search for params after host */
  //params = strchr(host, ';');  /* search for params after host */
  /* TODO: Recalculate the actual 'length' */
  params = (char *)::memchr(host, ';', length);  /* search for params after host */
/*  if (params == NULL)
    params = headers;
  else */
  if (params != NULL)
    /* params exist */
  {
/*
    char* tmpbuf;

    if (headers - params + 1 < 2)
      return OSIP_SYNTAXERROR;
    tmpbuf = osip_malloc(headers - params + 1);
    if (tmpbuf == NULL)
      return OSIP_NOMEM;
    tmpbuf = osip_strncpy(tmpbuf, params, headers - params);
    osip_uri_parse_params(url, tmpbuf);
    osip_free(tmpbuf);
*/
    ParseUriParams(params, length);
  }

  port = params - 1;
  while (port > host && *port != ']' && *port != ':')
    port--;
  if (*port == ':') 
  {
    if (host == port)
    {
      port = params;
    }
    else 
    {
      if ((params - port < 2) || (params - port > 8))
      {
        return 2; // OSIP_SYNTAXERROR;        /* error cases */
      }
/*
      url->port = (char*)osip_malloc(params - port);
      if (url->port == NULL)
        return OSIP_NOMEM;
      osip_clrncpy(url->port, port + 1, params - port - 1);
*/
      this->port.start = (port + 1 - &buf[0]);
      this->port.length = params - port - 1;
    }
  }
  else
  {
    port = params;
  }
  /* adjust port for ipv6 address */
  tmp = port;
  while (tmp > host && *tmp != ']')
  {
    tmp--;
  }
  if (*tmp == ']') 
  {
    port = tmp;
    while (host < port && *host != '[')
    {
      host++;
    }
    if (host >= port)
    {
      return 2; // OSIP_SYNTAXERROR;
    }
  }

  if (port - host < 2)
  {
    return 2; // OSIP_SYNTAXERROR;
  }
/*
  url->host = (char*)osip_malloc(port - host);
  if (url->host == NULL)
    return OSIP_NOMEM;
  osip_clrncpy(url->host, host + 1, port - host - 1);
*/
  this->host.start = host + 1 -&buf[0];
  this->host.length = port - host - 1;

  return 0;
}
#endif

#if 0
/* Based on osip_uri_parse but no memory creation */
int SipUri::ParseUri(const char* buf, size_t pos, size_t length)
{
  const char* tmp = NULL;
  const char* host = NULL;
  const char* username = NULL;
  const char* password = NULL;
  const char* headers = NULL;
  const char* params = NULL;
  const char* port = NULL;

  //size_t pos = 0;

  /* basic tests */
  if (buf == NULL || buf[pos] == '\0')
    return 1; //OSIP_BADPARAMETER;
 /* (1) we prefer to go one by one
  * (2) TODO: use memchr if necessary
  */

  tmp = (char*)::memchr(buf, ':', length);
  if ((tmp == NULL) || (tmp - buf < 2))
  {
    return 2; // OSIP_SYNTAXERROR;
  }
  //  if (tmp - buf < 2)
  //    return 2; // OSIP_SYNTAXERROR;

    /* TODO: Think about if checking to see scheme part for being alpha is necessary */
  /*
    i = 0;
    while (buf + i < tmp) {
      if (!osip_is_alpha(buf[i]))
        return OSIP_SYNTAXERROR;
      i++;
    }
  */

  /*
    url->scheme = (char*)osip_malloc(tmp - buf + 1);
    if (url->scheme == NULL)
      return OSIP_NOMEM;
    osip_strncpy(url->scheme, buf, tmp - buf);
  */
  this->scheme.start = pos; // buf[0];
  this->scheme.length = tmp - buf;
  /* TODO: Not sure the following check is needed */
/*
  if (strchr(url->scheme, ' ') != NULL) {
    return OSIP_SYNTAXERROR;
  }
*/

/* TODO: May be used a generic URI parsing logic as based on registered handlers */
#if 0
  if (strlen(url->scheme) < 3 || (0 != osip_strncasecmp(url->scheme, "sip", 3)
    && 0 != osip_strncasecmp(url->scheme, "sips", 4))) {        /* Is not a sipurl ! */
    size_t i = strlen(tmp + 1);

    if (i < 2)
      return OSIP_SYNTAXERROR;
    url->string = (char*)osip_malloc(i + 1);
    if (url->string == NULL)
      return OSIP_NOMEM;
    osip_strncpy(url->string, tmp + 1, i);
    return OSIP_SUCCESS;
  }
#endif

  /*  law number 1:
     if ('?' exists && is_located_after '@')
     or   if ('?' exists && '@' is not there -no username-)
     =====>  HEADER_PARAM EXIST
     =====>  start at index(?)
     =====>  end at the end of url
   */

   /* TODO: Not sure the following is ready */
#if 0
  /* find the beginning of host */
  username = strchr(buf, ':');
  /* if ':' does not exist, the url is not valid */
  if (username == NULL)
    return OSIP_SYNTAXERROR;
#endif
  username = tmp;

  //host = strchr(buf, '@');
  /* TODO: Recalculate the actual "length" */
  host = (char*)::memchr(buf, '@', length);
  if (host == NULL)
  {
    host = username;
  }
  else if (username[1] == '@')  /* username is empty */
  {
    host = username + 1;
  }
  else
    /* username exists */
  {
    //password = next_separator(username + 1, ':', '@');
    int l1 = host - username - 1;
    password = (char*)::memchr(username + 1, ':', host - username - 1);
    if (password == NULL)
    {
      password = host;
    }
    else
      /* password exists */
    {
      if (host - password < 2)
      {
        return 2; // OSIP_SYNTAXERROR;
      }
      /*
      url->password = (char*)osip_malloc(host - password);
      if (url->password == NULL)
        return OSIP_NOMEM;
      osip_strncpy(url->password, password + 1, host - password - 1);
      */
      this->password.start = (password - &buf[pos]) + 1;
      this->password.length = host - password - 1;

      /* TODO: This unscape replacement may be executed during creation of
               a copy for upper layer. An utility may also be created for upper layer */
               //__osip_uri_unescape(url->password);
    }
    if (password - username < 2)
    {
      return 2; // OSIP_SYNTAXERROR;
    }

    //{
    /*
      url->username = (char*)osip_malloc(password - username);
      if (url->username == NULL)
        return OSIP_NOMEM;
      osip_strncpy(url->username, username + 1, password - username - 1);
    */
    this->username.start = (username - &buf[pos]) + 1;
    this->username.length = password - username - 1;
#if 0
    /* TODO: This unscape replacement may be executed during creation of
               a copy for upper layer. An utility may also be created for upper layer */
               //  __osip_uri_unescape(url->username);
               //}

               /* search for header after host */
               //headers = strchr(host, '?');
               /* TODO: Recalculate the actual "length" */
    headers = (char*)::memchr(host, '?', length);
    /*    if (headers == NULL)
        {
          headers = buf + strlen(buf);
        }
        else*/
    if (headers != NULL)
    {
      /* headers exist */
      ParseUriHeaders(headers, length - (headers - buf));
    }
#endif
  }

  /* search for params after host */
  //params = strchr(host, ';');  /* search for params after host */
  /* TODO: Recalculate the actual 'length' */
  host++; /* skip '@' char */
  int l2 = length - (host - buf); /* length of chars from host to the end */

  int hostend = -1;
  /* Approximately detect the end the host part.
     first check if we have an uri header */
  headers = (char*)::memchr(host, '?', l2);
  if (headers != NULL)
  {
    hostend = headers - buf;
  }
  /* if not or if it appears after a semi-colon then the end of the
     address would be a uri param. */
  params = (char*)::memchr(host, ';', l2);  /* search for params after host */
  int parmindex = -1;
  if (params != NULL)
  {
    parmindex = params - buf;
  }

  if ((hostend == -1) || ((parmindex != -1) && (hostend > parmindex)))
  {
    hostend = parmindex;
  }
#if 0 
  if ((headers == NULL) || ((params != NULL) && (headers > params)))
  {
    l3 = params - buf; /* the end of host part */
  }
#endif
  /* if there was no header param either the address continues until 
     the end of the buffer */
  if (hostend == -1)
  {
    hostend = length;
  }

  ParseHostPortPair(pos, host, hostend);


/*  if (params == NULL)
    params = headers;
  else */
  if (params != NULL)
    /* params exist */
  {
    /*
        char* tmpbuf;

        if (headers - params + 1 < 2)
          return OSIP_SYNTAXERROR;
        tmpbuf = osip_malloc(headers - params + 1);
        if (tmpbuf == NULL)
          return OSIP_NOMEM;
        tmpbuf = osip_strncpy(tmpbuf, params, headers - params);
        osip_uri_parse_params(url, tmpbuf);
        osip_free(tmpbuf);
    */
    ParseUriParams(params, length);
  }

#if 0
  if (params)
  {
    port = params - 1;
  }
  else
  {
    port = buf 
  }
#endif
  port = &buf[hostend];

  while (port > host && *port != ']' && *port != ':')
  {
    port--;
  }
  if (*port == ':')
  {
    /* Consider IPv6 address with no square brackets '[' and ']' */
    if ((host == port) || (*(port - 1) != ']'))
    {
      //port = params;
      port = &buf[hostend]; // restore previous
    }
    else
    {
      if ((params - port < 2) || (params - port > 8))
      {
        return 2; // OSIP_SYNTAXERROR;        /* error cases */
      }
      /*
            url->port = (char*)osip_malloc(params - port);
            if (url->port == NULL)
              return OSIP_NOMEM;
            osip_clrncpy(url->port, port + 1, params - port - 1);
      */
      this->port.start = (port + 1 - &buf[0]);
      this->port.length = params - port - 1;
    }
  }
  else
  {
    //port = params;
    port = &buf[hostend]; // restore previous
  }
  /* adjust port for ipv6 address */
  tmp = port;
  while (tmp > host && *tmp != ']')
  {
    tmp--;
  }
  if (*tmp == ']')
  {
    port = tmp;
    while (host < port && *host != '[')
    {
      host++;
    }
    if (host >= port)
    {
      return 2; // OSIP_SYNTAXERROR;
    }
  }

  if (port - host < 2)
  {
    return 2; // OSIP_SYNTAXERROR;
  }
  /*
    url->host = (char*)osip_malloc(port - host);
    if (url->host == NULL)
      return OSIP_NOMEM;
    osip_clrncpy(url->host, host + 1, port - host - 1);
  */
  this->host.start = host - &buf[pos];
  this->host.length = port - host;

  return 0;
}
#endif

#if 0
int SipUri::ParseUri(const char* buf, size_t pos, size_t length)
{
  const char* tmp = NULL;
  const char* userOrHost = NULL;
  const char* passOrPort = NULL;
  const char* possibleHost = NULL;
  const char* passwd = NULL;
  const char* headers = NULL;
  const char* params = NULL;
  const char* tport = NULL;

  size_t remainingLength = length;
  int hostend = -1;
  int parmindex = -1;

  /* basic tests */
  if (buf == NULL || buf[pos] == '\0')
  {
    return 1; //OSIP_BADPARAMETER;
  }
  tmp = (char*)::memchr(buf, ':', length);
  if ((tmp == NULL) || (tmp - buf < 2))
  {
    return 2; // OSIP_SYNTAXERROR;
  }

  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = length;
  this->rawdata._pos = pos;

  this->scheme.start = pos; 
  this->scheme.length = tmp - buf;
  /* NOTE: Verification of the scheme if it is 'sip' or 'sips' or any other
           type of protocol will not be performed here, i.e. during parsing
           phase. There should be an outer mechanism to do these kind of 
           checks. */

  userOrHost = tmp + 1; 
  remainingLength = length - (userOrHost - buf);
  possibleHost = (char*)::memchr(userOrHost, '@', (length - (userOrHost - buf)));
  if (possibleHost != NULL)
  {
    /* userOrHost indicates a userinfo */
    size_t uinfoLength = possibleHost - userOrHost;
    /* see if userinfo consists of password */
    passwd = (char*)::memchr(userOrHost, ':', uinfoLength);
    if (passwd != NULL)
    {
      this->password.start = passwd + 1 /* to skip ':" char */ - buf + pos;
      this->password.length = uinfoLength - (passwd + 1 - userOrHost);
    }
    else
    {
      passwd = userOrHost + uinfoLength;
    }
    this->username.start = userOrHost - buf + pos;
    this->username.length = passwd - userOrHost;

    /* to continue with host part of URI */
  }
  else 
  {
    /* userOrHost indicates host part of URI */
    possibleHost = userOrHost;
  }

  remainingLength = length - (possibleHost - buf);
  /* Approximately detect the end the host part. 
     First check if we have an uri header */
  headers = (char*)::memchr(possibleHost, '?', remainingLength);
  if (headers != NULL)
  {
    hostend = headers - buf;
  }
  /* if not or if it appears after a semi-colon then the end of the
     address would be a uri param. */
  params = (char*)::memchr(possibleHost, ';', remainingLength);  /* search for params after host */
  if (params != NULL)
  {
    parmindex = params - buf;
  }

  if ((hostend == -1) || ((parmindex != -1) && (hostend > parmindex)))
  {
    hostend = parmindex;
  }  
  /* if there was no header param either the address continues until
     the end of the buffer */
  if (hostend == -1)
  {
    hostend = length;
  }
  
  tport = &buf[hostend];

  while (tport > possibleHost && *tport != ']' && *tport != ':')
  {
    tport--;
  }
  if (*tport == ':')
  {
    /* Consider IPv6 address with no square brackets '[' and ']' */
    if ((possibleHost == tport) || (*(tport - 1) != ']'))
    {
      //port = params;
      tport = &buf[hostend]; // restore previous
    }
    else
    {
      if ((&buf[hostend] - tport < 2) || (&buf[hostend] - tport > 8))
      {
        return 2; // OSIP_SYNTAXERROR;        /* error cases */
      }
      /*
            url->port = (char*)osip_malloc(params - port);
            if (url->port == NULL)
              return OSIP_NOMEM;
            osip_clrncpy(url->port, port + 1, params - port - 1);
      */
      this->port.start = (tport + 1 - &buf[pos]);
      this->port.length = &buf[hostend] - tport - 1;
    }
  }
  else
  {
    //port = params;
    tport = &buf[hostend]; // restore previous
  }
  // TODO: Not sure the following is necessary (got from osip)
#if 0
  /* adjust port for ipv6 address */
  tmp = tport;
  while (tmp > possibleHost && *tmp != ']')
  {
    tmp--;
  }
  if (*tmp == ']')
  {
    tport = tmp;
    while (possibleHost < tport && *possibleHost != '[')
    {
      possibleHost++;
    }
    if (possibleHost >= tport)
    {
      return 2; // OSIP_SYNTAXERROR;
    }
  }

  if (tport - possibleHost < 2)
  {
    return 2; // OSIP_SYNTAXERROR;
  }
#endif
  /*
    url->host = (char*)osip_malloc(port - host);
    if (url->host == NULL)
      return OSIP_NOMEM;
    osip_clrncpy(url->host, host + 1, port - host - 1);
  */
  /* NOTE: Logically there is a need to verify the format, characters etc. 
           It is considered that this could be done with a separate mechnism */
  this->host.start = possibleHost + 1 - &buf[pos];
  this->host.length = tport - possibleHost - 1;

}

int SipUri::ParseHostPortPair(size_t pos, const char* hostport, size_t length)
{
  // Take into consideration IPv6 format when locating port.
//  const char* lColon = (char*)::memrchr(hostport, ':', length);
//  int rBracketIndex = address.indexOf(']');

  return 0;
}

int SipUri::ParseUriHeaders(const char* buf, size_t length)
{
  return 0;
}

int SipUri::ParseUriParams(const char* buf, size_t length)
{
  return 0;
}
#endif

#if 0
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_DIGIT(c)         ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_DIGIT(c))
#define IS_HEX(c)           (IS_DIGIT(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_UNRESERVED(c)    (IS_ALPHANUM(c) || IS_MARK(c))
#define IS_ESCAPED_CHAR(c)  ((c) == '%')
#endif

/* RFC 3261: user-unreserved: "&" / "=" / "+" / "$" / "," / ";" / "?" / "/" */
#define IS_USER_UNRESERVED(c)  ((c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',' || (c) == ';' || (c) == '?' || (c) == '/')

#define IS_USERINFO_CHAR(c) (IS_UNRESERVED(c) || IS_USER_UNRESERVED(c) || \
  IS_ESCAPED_CHAR(c))
//#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
//  (c) == ';' || (c) == ':' || (c) == '&' || (c) == '=' || (c) == '+' || \
//  (c) == '$' || (c) == ',')

#define IS_HOST_CHAR(c)     (IS_ALPHANUM(c) || (c) == '.' || (c) == '-')

#define IS_PASSWORD_CHAR(c) (IS_UNRESERVED(c) || IS_ESCAPED_CHAR(c) || \
  (c) == '&' || (c) == '=' || (c) == '+' || (c) == '$' || (c) == ',')
#if 0
/* paramchar         =  param-unreserved / unreserved / escaped
   param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$" 
 */
#define IS_PARAM_UNRESERVED(c) ((c) == '[' || (c) == ']' || (c) == '/' || \
  (c) == ':' || (c) == '&' || (c) == '+' || (c) == '$' )
#define IS_PARAM_CHAR(c)    (IS_PARAM_UNRESERVED(c) || IS_UNRESERVED(c) || \
  IS_ESCAPED_CHAR(c))
#endif

/* hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$" */
#define IS_URL_HEADER_CHAR(c)  (IS_UNRESERVED(c) || IS_ESCAPED_CHAR(c) || \
  (c) == '[' || (c) == ']' || (c) == '/' || (c) == '?' || (c) == ':' || \
  (c) == '+' || (c) == '$')

enum url_parsing_state
{   s_url_dead = 1
  , s_url_spaces_before_url
  , s_url_scheme
  , s_url_user_or_host_start
  , s_url_user_or_host
  , s_url_passwd_or_port_start
  , s_url_passwd_or_port
  , s_url_host_start
  , s_url_host
  , s_url_host_v6_start
  , s_url_host_v6
  , s_url_host_v6_end
  , s_url_host_port_start
  , s_url_host_port
  , s_url_param_start
  , s_url_param_name
  , s_url_param_value_start
  , s_url_param_value
  , s_url_header_start
  , s_url_header_name
  , s_url_header_value_start
  , s_url_header_value

};

static enum url_parsing_state parse_url_char(enum url_parsing_state s, const char ch)
{
  if (ch == ' ' || ch == '\r' || ch == '\n') 
  {
    /* Considered that all space before calling this method shall be skipped */
    return s_url_dead;
  }

#if URL_PARSER_STRICT
  if (ch == '\t' || ch == '\f') {
    return s_dead;
  }
#endif

  switch (s) 
  {
    case s_url_spaces_before_url:
      if (IS_ALPHA(ch)) 
      {
        return s_url_scheme;
      }
      break;

    case s_url_scheme:
      if (IS_ALPHA(ch)) 
      {
        return s;
      }
      if (ch == ':') 
      {
        return s_url_user_or_host_start;
      }
      break;

    case s_url_user_or_host_start:
      if (IS_USERINFO_CHAR(ch))
      {
        return s_url_user_or_host;
      }
      break;

    // NOTE: user may contain ';', host may not...
    case s_url_user_or_host:
      if (IS_USERINFO_CHAR(ch))
      {
        return s;
      }
      if (ch == ':')
      {
        return s_url_passwd_or_port_start;
      }
      if (ch == '@') 
      {
        return s_url_host_start;
      }
      break;

    case s_url_passwd_or_port_start:
      if (IS_PASSWORD_CHAR(ch))
      {
        return s_url_passwd_or_port;
      }
      break;

    /* we collect according to password */
    case s_url_passwd_or_port:
      if (IS_PASSWORD_CHAR(ch))
      {
        return s;
      }
      if (ch == '@')
      {
        return s_url_host_start;
      }
      break;

    case s_url_host_start:
      if (ch == '[')
      {
        return s_url_host_v6_start;
      }
      if (IS_HOST_CHAR(ch))
      {
        return s_url_host;
      }
      break;

    case s_url_host_v6_start:
      if (IS_HEX(ch) || ch == ':' || ch == '.') 
      {
        return s_url_host_v6;
      }
      break;

    case s_url_host_v6:
      if (IS_HEX(ch) || ch == ':' || ch == '.') 
      {
        return s_url_host_v6;
      }
      if (ch == ']')
      {
        //return s_url_host;
        return s_url_host_v6_end;
      }
      break;
/*
    case s_url_host_v6_end:
      if (ch == ':')
      {
        return s_url_host_port_start;
      }
      if (ch == ';')
      {
        return s_url_param_start;
      }
      if (ch == '?')
      {
        return s_url_header_start;
      }
      break;
*/
    case s_url_host:
      if (IS_HOST_CHAR(ch))
      {
        return s;
      }

    /* fall through */
    case s_url_host_v6_end:
      if (ch == ':')
      {
        return s_url_host_port_start;
      }
      if (ch == ';')
      {
        return s_url_param_start;
      }
      if (ch == '?')
      {
        return s_url_header_start;
      }
      break;

    case s_url_host_port_start:
      /* at least 1 DIGIT is expected for port */
      if (IS_DIGIT(ch))
      {
        return s_url_host_port;
      }
      break;

    case s_url_host_port:
    //case s_url_host_port_start:
      if (IS_DIGIT(ch)) 
      {
        return s_url_host_port;
      }
      if (ch == ';')
      {
        return s_url_param_start;
      }
      if (ch == '?')
      {
        return s_url_header_start;
      }
      break;

    case s_url_param_start:
      if (IS_PARAM_CHAR(ch))
      {
        return s_url_param_name;
      }
#if 0
      if (ch == '=')
      {
        return s_url_param_value_start;
      }
#endif
      break;

    case s_url_param_name:
      if (IS_PARAM_CHAR(ch))
      {
        return s;
      }
      if (ch == '=')
      {
        return s_url_param_value_start;
      }
      if (ch == ';')
      {
        /* this param does not have a value field, starting a new param */
        return s_url_param_start;
      }
      if (ch == '?')
      {
        /* this param does not have a value field, starting an url-header */
        return s_url_header_start;
      }
      break;

    case s_url_param_value_start:
      if (IS_PARAM_CHAR(ch))
      {
        return s_url_param_value;
      }
      break;

    case s_url_param_value:
      if (IS_PARAM_CHAR(ch))
      {
        return s_url_param_value;
      }
      if (ch == ';')
      {
        return s_url_param_start;
      }
      if (ch == '?')
      {
        return s_url_header_start;
      }
      break;

    case s_url_header_start:
      if (IS_URL_HEADER_CHAR(ch))
      {
        return s_url_header_name;
      }
      break;

    case s_url_header_name:
      if (IS_URL_HEADER_CHAR(ch))
      {
        return s;
      }
      if (ch == '=')
      {
        return s_url_header_value_start;
      }
      break;

    case s_url_header_value_start:
      if (IS_URL_HEADER_CHAR(ch))
      {
        return s_url_header_value;
      }
      break;

    case s_url_header_value:
      if (IS_URL_HEADER_CHAR(ch))
      {
        return s;
      }
      if (ch == '&')
      {
        return s_url_header_start;
      }
      break;

    default:
      break;
  }

  /* We should never fall out of the switch above unless there's an error */
  return s_url_dead;
}

int SipUri::ParseUri(const char* buf, size_t pos, size_t buflen)
{
  enum url_parsing_state s = s_url_spaces_before_url;
  enum url_parsing_state prev_s = s_url_spaces_before_url;
  const char* scheme_mark = NULL;
  const char* user_or_host_mark = NULL;
  const char* passwd_or_port_mark = NULL;
  const char* host_mark = NULL;
  const char* port_mark = NULL;
  const char* param_name_mark = NULL;
  const char* param_value_mark = NULL;
  const char* header_name_mark = NULL;
  const char* header_value_mark = NULL;
  //header_pos_t* current_param = NULL;
  param_pos_t* current_param = NULL;
  header_pos_t* current_header = NULL;

  bool reparsing = false;

  const char* p;

  if (buflen == 0) 
  {
    return 1;
  }

  this->rawdata._data = (unsigned char*)buf;
  this->rawdata._length = buflen;
  this->rawdata._pos = pos;

reparse:
  //for (p = buf + pos; p < buf + pos + buflen; p++)
  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_url_char(s, *p);

    switch (s)
    {
      case s_url_dead:
        return 1;

      case s_url_scheme:
        if (prev_s == s_url_spaces_before_url)
        {
          scheme_mark = p;
        }
        break;

      case s_url_user_or_host_start:
        if (prev_s == s_url_scheme)
        {
          this->uri.scheme.start = (uint32_t)(scheme_mark - buf);
          this->uri.scheme.length = (uint32_t)(p - scheme_mark);
          if (reparsing)
          {
            s = s_url_host_start;
          }
        }
        break;

      case s_url_user_or_host:
        if (prev_s == s_url_user_or_host_start)
        {
          user_or_host_mark = p;
        }
        break;

      case s_url_passwd_or_port_start:
        if (prev_s == s_url_user_or_host)
        {
          /* although it is not certain that we are collecting username and password,
             for now we consider this */
          this->uri.username.start = (uint32_t)(user_or_host_mark - buf);
          this->uri.username.length = (uint32_t)(p - user_or_host_mark);
        }
        break;

      case s_url_passwd_or_port:
        if (prev_s == s_url_passwd_or_port_start)
        {
          passwd_or_port_mark = p;
        }
        break;

      case s_url_host_start:
        if (prev_s == s_url_user_or_host)
        {
          /* now it is certain that we have collected username */
          this->uri.username.start = (uint32_t)(user_or_host_mark - buf);
          this->uri.username.length = (uint32_t)(p - user_or_host_mark);
        }
        else if (prev_s == s_url_passwd_or_port)
        {
          this->uri.password.start = (uint32_t)(passwd_or_port_mark - buf);
          this->uri.password.length = (uint32_t)(p - passwd_or_port_mark);
        }
        break;

      case s_url_host:
        if (prev_s == s_url_host_start)
        {
          host_mark = p;
        }
        break;

      case s_url_host_v6_start:
        if (prev_s == s_url_host_start)
        {
          host_mark = p;
        }
        break;

      case s_url_host_v6:
      case s_url_host_v6_end:
        /* no action required */
        break;

      case s_url_host_port_start:
        if ((prev_s == s_url_host) || (prev_s == s_url_host_v6_end))
        {
          /* host completed. Wait for port or url-params or url-headers */
          this->uri.host.start = host_mark - buf;
          this->uri.host.length = p - host_mark;
        }
        break;

      case s_url_host_port:
        if (prev_s == s_url_host_port_start)
        {
          port_mark = p;
        }
        break;

      case s_url_param_start:
        if ((prev_s == s_url_host) || (prev_s == s_url_host_v6_end))
        {
          this->uri.host.start = host_mark - buf;
          this->uri.host.length = p - host_mark;
        }
        else if (prev_s == s_url_host_port)
        {
          this->uri.port.start = port_mark - buf;
          this->uri.port.length = p - port_mark;
        }
        else if (prev_s == s_url_param_name)
        {
          /* a parameter with no value part is completed */
          current_param->type.start = param_name_mark - buf;
          current_param->type.length = p - param_name_mark;
        }
        else if (prev_s == s_url_param_value)
        {
          /* value part of a parameter is completed */
          current_param->value.start = param_value_mark - buf;
          current_param->value.length = p - param_value_mark;
        }
        break;

      case s_url_param_name:
        if (prev_s == s_url_param_start)
        {
          param_name_mark = p;
          current_param = &this->uri.urlParams[this->uri.num_params++];
        }
        break;

      case s_url_param_value_start:
        if (prev_s == s_url_param_name)
        {
          /* name part of a parameter is completed */
          current_param->type.start = param_name_mark - buf;
          current_param->type.length = p - param_name_mark;
          /* wait for the value part to be collected */
        }
        break;

      case s_url_param_value:
        if (prev_s == s_url_param_value_start)
        {
          param_value_mark = p;
        }
        break;

      case s_url_header_start:
        if ((prev_s == s_url_host) || (prev_s == s_url_host_v6_end))
        {
          this->uri.host.start = host_mark - buf;
          this->uri.host.length = p - host_mark;
        }
        else if (prev_s == s_url_host_port)
        {
          this->uri.port.start = port_mark - buf;
          this->uri.port.length = p - port_mark;
        }
        else if (prev_s == s_url_param_name)
        {
          /* a parameter with no value part is completed */
          current_param->type.start = param_name_mark - buf;
          current_param->type.length = p - param_name_mark;
        }
        else if (prev_s == s_url_param_value)
        {
          /* value part of a parameter is completed */
          current_param->value.start = param_value_mark - buf;
          current_param->value.length = p - param_value_mark;
        }
        else if (prev_s == s_url_header_value)
        {
          /* value part of a header is completed */
          current_header->valuepos.start = header_value_mark - buf;
          current_header->valuepos.length = p - header_value_mark;
        }
        break;

      case s_url_header_name:
        if (prev_s == s_url_header_start)
        {
          header_name_mark = p;
          /* starts a new header */
          current_header = &this->uri.urlHeaders[this->uri.num_headers++];
        }
        break;

      case s_url_header_value_start:
        if (prev_s == s_url_header_name)
        {
          /* name part of a header is completed */
          current_header->fieldpos.start = header_name_mark - buf;
          current_header->fieldpos.length = p - header_name_mark;
          /* wait for completion of value part to add into the list */
        }
        break;

      case s_url_header_value:
        if (prev_s == s_url_header_value_start)
        {
          header_value_mark = p;
        }
        break;
    }

    prev_s = s;
  }

  /* completed the buffer processing. Check for the last state to complete the job */
  if (s == s_url_header_value)
  {
    /* consider name part of a header is completed */
    current_header->valuepos.start = header_value_mark - buf;
    current_header->valuepos.length = p - header_value_mark;
    return 0;
  }
  if (s == s_url_param_value)
  {
    /* consider value part of a parameter is completed */
    current_param->value.start = param_value_mark - buf;
    current_param->value.length = p - param_value_mark;
    return 0;
  }
  if (s == s_url_param_name)
  {
    /* consider a parameter with no value part is completed */
    current_param->type.start = param_name_mark - buf;
    current_param->type.length = p - param_name_mark;
    return 0;
  }
  if ((s == s_url_host) || (s == s_url_host_v6_end))
  {
    this->uri.host.start = host_mark - buf;
    this->uri.host.length = p - host_mark;
    return 0;
  }
  if (s == s_url_host_port)
  {
    this->uri.port.start = port_mark - buf;
    this->uri.port.length = p - port_mark;
    return 0;
  }
  if (s == s_url_user_or_host)
  {
    /* This is the special case where there is no userinfo part of
       the URI and start with host and others. We select the way 
       re-invocation  with s_url_host */
    s = s_url_host;
    prev_s = s_url_host_start; /* to be able to set host_mark */
    /* we have to skip scheme part */
    pos += this->uri.scheme.length + 1; /* +1 is to skip ':' */
    goto reparse;
  }

  /* completed in an inappropriate state */
  return 1;
}

void SipUri::PrintOut(std::ostringstream& buf)
{
  buf << "-------- SIP URI DUMP ----------\n";
  buf << "scheme   = " << std::string((const char*)this->rawdata._data + this->uri.scheme.start, this->uri.scheme.length) << std::endl;
  if (this->uri.username.length > 0)
  {
    buf << "username = " << std::string((const char*)this->rawdata._data + this->uri.username.start, this->uri.username.length) << std::endl;
  }
  if (this->uri.password.length > 0)
  {
    buf << "password = " << std::string((const char*)this->rawdata._data + this->uri.password.start, this->uri.password.length) << std::endl;
  }
  if (this->uri.host.length > 0)
  {
    buf << "host     = " << std::string((const char*)this->rawdata._data + this->uri.host.start, this->uri.host.length) << std::endl;
  }
  if (this->uri.port.length > 0)
  {
    buf << "port     = " << std::string((const char*)this->rawdata._data + this->uri.port.start, this->uri.port.length) << std::endl;
  }
  if (this->uri.num_params)
  {
    buf << "---------- Parameters ----------\n";
    for (int i = 0; i < this->uri.num_params; i++)
    {
      buf << std::string((const char*)this->rawdata._data + this->uri.urlParams[i].type.start, this->uri.urlParams[i].type.length);
      if (this->uri.urlParams[i].value.length)
      {
        buf << '=';
        buf << std::string((const char*)this->rawdata._data + this->uri.urlParams[i].value.start, this->uri.urlParams[i].value.length);
        buf << std::endl;
      }
    }
  }
  if (this->uri.num_headers)
  {
    buf << "---------- Headers ----------\n";
    for (int i = 0; i < this->uri.num_headers; i++)
    {
      buf << std::string((const char*)this->rawdata._data + this->uri.urlHeaders[i].fieldpos.start, this->uri.urlHeaders[i].fieldpos.length);
      if (this->uri.urlParams[i].value.length)
      {
        buf << '=';
        buf << std::string((const char*)this->rawdata._data + this->uri.urlHeaders[i].valuepos.start, this->uri.urlHeaders[i].valuepos.length);
        buf << std::endl;
      }
    }
  }

  buf << "----------------\n";
  buf << "uri --> " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
  buf << "---------------------------------------\n";
}

