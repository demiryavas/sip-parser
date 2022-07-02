#include "ViaHeader.h"

#include "Utility.h"
/*
  The Via header field indicates the path taken by the request so far
  and indicates the path that should be followed in routing responses.
  The branch ID parameter in the Via header field values serves as a
  transaction identifier, and is used by proxies to detect loops.

  A Via header field value contains the transport protocol used to send
  the message, the client's host name or network address, and possibly
  the port number at which it wishes to receive responses.  A Via
  header field value can also contain parameters such as "maddr",
  "ttl", "received", and "branch", whose meaning and use are described
  in other sections.  For implementations compliant to this
  specification, the value of the branch parameter MUST start with the
  magic cookie "z9hG4bK".

  Transport protocols defined here are "UDP", "TCP", "TLS", and "SCTP".
  "TLS" means TLS over TCP.  When a request is sent to a SIPS URI, the
  protocol still indicates "SIP", and the transport protocol is TLS.

  The compact form of the Via header field is v.

  Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7
  Via: SIP/2.0/UDP 192.0.2.1:5060 ;received=192.0.2.207
     ;branch=z9hG4bK77asjd

  The host or network address and port number are not required to
  follow the SIP URI syntax.  Specifically, LWS on either side of the
  ":" or "/" is allowed, as shown here:

  Via: SIP / 2.0 / UDP first.example.com: 4000;ttl=16
        ;maddr=224.2.0.1 ;branch=z9hG4bKa7c6a8dlze.1

  Via               =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
  via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
  via-params        =  via-ttl / via-maddr
                       / via-received / via-branch
                       / via-extension
  via-ttl           =  "ttl" EQUAL ttl
  via-maddr         =  "maddr" EQUAL host
  via-received      =  "received" EQUAL (IPv4address / IPv6address)
  via-branch        =  "branch" EQUAL token
  via-extension     =  generic-param
  sent-protocol     =  protocol-name SLASH protocol-version
                       SLASH transport
  protocol-name     =  "SIP" / token
  protocol-version  =  token
  transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
                       / other-transport
  sent-by           =  host [ COLON port ]
  ttl               =  1*3DIGIT ; 0 to 255

  token             =  1*(alphanum / "-" / "." / "!" / "%" / "*"
                       / "_" / "+" / "`" / "'" / "~" )

  WARNING: A Via header may consist of multiple Via headers separated by ','
*/

enum via_sby_parsing_state
{
  s_sby_dead = 1
  , s_sby_spaces_before_value
  , s_sby_protocol_name
  , s_sby_protocol_name_lws
  , s_sby_protocol_version_start
  , s_sby_protocol_version_start_lws
  , s_sby_protocol_version
  , s_sby_protocol_version_lws
  , s_sby_transport_start
  , s_sby_transport_start_lws
  , s_sby_transport
  , s_sby_transport_lws
  , s_sby_sentby_host
  , s_sby_sentby_host_lws
  , s_sby_sentby_host_v6_start
  , s_sby_sentby_host_v6
  , s_sby_sentby_host_v6_end
  , s_sby_sentby_host_v6_end_lws
  , s_sby_sentby_port_start
  , s_sby_sentby_port_start_lws
  , s_sby_sentby_port
  , s_sby_sentby_port_lws
  , s_sby_param_start
};

/* NOTE: The approach here considers the variable part of a header has already been
         parsed/extracted before during general message parsing. Therefore, parsing
         does not consider folding i.e. when it encounters CRLFs it does not consider
         the end of header, it considers that the folding behavior has already been
         handled previously. */
enum via_sby_parsing_state parse_sentby_char(enum via_sby_parsing_state s, const char ch)
{
  switch (s)
  {
    case s_sby_spaces_before_value:
      if (IS_TOKEN(ch))
      {
        return s_sby_protocol_name;
      }
      if (IS_LWS(ch))
      {
        return s;
      }
      break;

    case s_sby_protocol_name:
      if (IS_TOKEN(ch))
      {
        return s_sby_protocol_name;
      }
      if (ch == '/')
      {
        return s_sby_protocol_version_start;
      }
      if (IS_LWS(ch))
      {
        return s_sby_protocol_name_lws;
      }
      break;

    case s_sby_protocol_name_lws:
      if (IS_LWS(ch))
      {
        return s_sby_protocol_name_lws;
      }
      if (ch == '/')
      {
        return s_sby_protocol_version_start;
      }
      break;

    case s_sby_protocol_version_start:
      if (IS_TOKEN(ch))
      {
        return s_sby_protocol_version;
      }
      if (IS_LWS(ch))
      {
        return s_sby_protocol_version_start_lws;
      }
      break;

    case s_sby_protocol_version_start_lws:
      if (IS_LWS(ch))
      {
        return s_sby_protocol_version_start_lws;
      }
      if (IS_TOKEN(ch))
      {
        return s_sby_protocol_version;
      }
      break;

    case s_sby_protocol_version:
      if (IS_TOKEN(ch))
      {
        return s_sby_protocol_version;
      }
      if (IS_LWS(ch))
      {
        return s_sby_protocol_version_lws;
      }
      if (ch == '/')
      {
        return s_sby_transport_start;
      }
      break;

    case s_sby_protocol_version_lws:
      if (IS_LWS(ch))
      {
        return s_sby_protocol_version_lws;
      }
      if (ch == '/')
      {
        return s_sby_transport_start;
      }
      break;

    case s_sby_transport_start:
      if (IS_TOKEN(ch))
      {
        return s_sby_transport;
      }
      if (IS_LWS(ch))
      {
        return s_sby_transport_start_lws;
      }
      break;

    case s_sby_transport_start_lws:
      if (IS_TOKEN(ch))
      {
        return s_sby_transport;
      }
      if (IS_LWS(ch))
      {
        return s_sby_transport_start_lws;
      }
      break;

    case s_sby_transport:
      if (IS_TOKEN(ch))
      {
        return s_sby_transport;
      }
      if (IS_LWS(ch))
      {
        return s_sby_transport_lws;
      }
      break;

    case s_sby_transport_lws:
      if (IS_LWS(ch))
      {
        return s_sby_transport_lws;
      }
      if (IS_HOST_CHAR(ch))
      {
        return s_sby_sentby_host;
      }
      if (ch == '[')
      {
        return s_sby_sentby_host_v6_start;
      }
      break;

    case s_sby_sentby_host:
      if (IS_HOST_CHAR(ch))
      {
        return s_sby_sentby_host;
      }
      if (ch == ':')
      {
        return s_sby_sentby_port_start;
      }
      if (IS_LWS(ch))
      {
        return s_sby_sentby_host_lws;
      }
      if (ch == ';')
      {
        return s_sby_param_start;
      }
      break;

    case s_sby_sentby_host_lws:
      if (IS_LWS(ch))
      {
        return s_sby_sentby_host_lws;
      }
      if (ch == ':')
      {
        return s_sby_sentby_port_start;
      }
      break;

    case s_sby_sentby_port_start:
      if (IS_DIGIT(ch))
      {
        return s_sby_sentby_port;
      }
      if (IS_LWS(ch))
      {
        return s_sby_sentby_port_start_lws;
      }
      break;

    case s_sby_sentby_host_v6_start:
      if (IS_HEX(ch) || ch == ':' || ch == '.')
      {
        return s_sby_sentby_host_v6;
      }
      break;

    case s_sby_sentby_host_v6:
      if (IS_HEX(ch) || ch == ':' || ch == '.')
      {
        return s_sby_sentby_host_v6;
      }
      if (ch == ']')
      {
        return s_sby_sentby_host_v6_end;
      }
      break;

    case s_sby_sentby_host_v6_end:
      if (IS_LWS(ch))
      {
        return s_sby_sentby_host_v6_end_lws;
      }
      if (ch == ':')
      {
        return s_sby_sentby_port_start;
      }
      if (ch == ';')
      {
        return s_sby_param_start;
      }
      break;

    case s_sby_sentby_port:
      if (IS_DIGIT(ch))
      {
        return s_sby_sentby_port;
      }
      if (IS_LWS(ch))
      {
        return s_sby_sentby_port_lws;
      }
      if (ch == ';')
      {
        return s_sby_param_start;
      }
      break;

    case s_sby_sentby_port_lws:
      if (IS_LWS(ch))
      {
        return s_sby_sentby_port_lws;
      }
      if (ch == ';')
      {
        return s_sby_param_start;
      }
      break;
  }
  return s_sby_dead;
}

const char* parse_via_sentby_part(const char* buf, size_t pos, size_t buflen, via_param_t* viaparam, int* parse_error)
{
  enum via_sby_parsing_state s = s_sby_spaces_before_value;
  enum via_sby_parsing_state prev_s = s_sby_spaces_before_value;
  const char* protname_mark = NULL;
  const char* protversion_mark = NULL;
  const char* transport_mark = NULL;
  const char* sbhost_mark = NULL;
  const char* sbport_mark = NULL;
  const char* param_name_mark = NULL;
  const char* param_value_mark = NULL;
  param_pos_t* current_param = NULL;

  const char* p;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_sentby_char(s, *p);

    switch (s)
    {
      case s_sby_dead:
        *parse_error = PARSING_FAILED_STATE_DEAD;
        return p;

      case s_sby_protocol_name:
        if (prev_s == s_sby_spaces_before_value)
        {
          protname_mark = p;
        }
        break;

      case s_sby_protocol_name_lws:
        if (prev_s == s_sby_protocol_name)
        {
          viaparam->protocol.start = protname_mark - buf;
          viaparam->protocol.length = p - protname_mark;
        }
        break;

      case s_sby_protocol_version_start:
        if (prev_s == s_sby_protocol_name)
        {
          viaparam->protocol.start = protname_mark - buf;
          viaparam->protocol.length = p - protname_mark;
        }
        break;

      case s_sby_protocol_version:
        if ((prev_s == s_sby_protocol_version_start) || (prev_s == s_sby_protocol_version_start_lws))
        {
          protversion_mark = p;
        }
        break;

      case s_sby_protocol_version_lws:
        if (prev_s == s_sby_protocol_version)
        {
          viaparam->version.start = protversion_mark - buf;
          viaparam->version.length = p - protversion_mark;
        }
        break;

      case s_sby_transport_start:
        if (prev_s == s_sby_protocol_version)
        {
          viaparam->version.start = protversion_mark - buf;
          viaparam->version.length = p - protversion_mark;
        }
        break;

      case s_sby_transport:
        if ((prev_s == s_sby_transport_start) || (prev_s == s_sby_transport_start_lws))
        {
          transport_mark = p;
        }
        break;

      case s_sby_transport_lws:
        if (prev_s == s_sby_transport)
        {
          viaparam->transport.start = transport_mark - buf;
          viaparam->transport.length = p - transport_mark;
        }
        break;

      case s_sby_sentby_host:
        if (prev_s == s_sby_transport_lws)
        {
          sbhost_mark = p;
        }
        break;

      case s_sby_sentby_host_lws:
        if (prev_s == s_sby_sentby_host)
        {
          viaparam->host.start = sbhost_mark - buf;
          viaparam->host.length = p - sbhost_mark;
        }
        break;

      case s_sby_sentby_port_start:
        if ((prev_s == s_sby_sentby_host) || (prev_s == s_sby_sentby_host_v6_end))
        {
          viaparam->host.start = sbhost_mark - buf;
          viaparam->host.length = p - sbhost_mark;
        }
        break;

      case s_sby_param_start:
        if ((prev_s == s_sby_sentby_host) || (prev_s == s_sby_sentby_host_v6_end))
        {
          viaparam->host.start = sbhost_mark - buf;
          viaparam->host.length = p - sbhost_mark;
        }
        else if (prev_s == s_sby_sentby_port)
        {
          viaparam->port.start = sbport_mark - buf;
          viaparam->port.length = p - sbport_mark;
        }
        return p;
        break;

      case s_sby_sentby_port:
        if ((prev_s == s_sby_sentby_port_start) || (prev_s == s_sby_sentby_port_start_lws))
        {
          sbport_mark = p;
        }
        break;

      case s_sby_sentby_port_lws:
        if (prev_s == s_sby_sentby_port)
        {
          viaparam->port.start = sbport_mark - buf;
          viaparam->port.length = p - sbport_mark;
        }
        break;

      case s_sby_sentby_host_v6_start:
        if (prev_s == s_sby_transport_lws)
        {
          sbhost_mark = p;
        }
        break;

      case s_sby_sentby_host_v6_end_lws:
        if (prev_s == s_sby_sentby_host_v6_end)
        {
          viaparam->host.start = sbhost_mark - buf;
          viaparam->host.length = p - sbhost_mark;
        }
        break;
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the current state to complete the job */
  switch (s)
  {
    case s_sby_sentby_host:
    case s_sby_sentby_host_v6_end:
    /* Set host and return. Seems that no port and params included */
    viaparam->host.start = sbhost_mark - buf;
    viaparam->host.length = p - sbhost_mark;
    break;

    case s_sby_sentby_port:
      /* Set port and return. Seems that no params included */
      viaparam->port.start = sbport_mark - buf;
      viaparam->port.length = p - sbport_mark;
      break;

    case s_sby_sentby_host_lws:
    case s_sby_sentby_host_v6_end_lws:
    case s_sby_sentby_port_lws:
      /* Nothing to set but seems that no port and params included */
      break;

    case s_sby_param_start:
      /* In the case of external-parsing of parameter part */
      break;

    default:
      *parse_error = 1;
      break;
  }
  return p;
}

const char* ViaHeader:: ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
  int result = 0;
  int parse_error = 0;

  const char* p;

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
    via_param_t* viaparam = &this->via_parms[this->num_via_parms++];
    p = parse_via_sentby_part(buf, p - buf, buflen, viaparam, &parse_error);
    if (parse_error)
    {
      this->parsing_stat = (ParsingStatus_t)parse_error;
      return p;
    }
//    /* TODO: not sure the following is necessary */
//    if (p == NULL)
//    {
//      this->parsing_stat = PARSING_FAILED;
//      return 1;
//    }
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
        p = parse_param_part(buf, p - buf, buflen, &viaparam->params[0], MAX_NUM_PARAMS, &viaparam->num_params, &parse_error, 1);
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
    }
  }

  this->parsing_stat = (parse_error) ? PARSING_FAILED_UNCLEAR_REASON : PARSED_SUCCESSFULLY;
  return p;
}

/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
std::string ViaHeader::GetHeaderValue()
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
  for (int i = 0; i < this->num_via_parms; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      sbuf.append(1, ',');
    }
    via_param_t* viaparam = &this->via_parms[i];

    /* check for mandatory parts if exist */
    if (!(this->rawdata._length) || !(viaparam->protocol.length) ||
        !(viaparam->version.length) || !(viaparam->host.length))
    {
      return "";
    }
    size_t length = (size_t)this->rawdata._length;
    sbuf.reserve(length);
    sbuf.append((const char*)this->rawdata._data + viaparam->protocol.start, viaparam->protocol.length);
    sbuf.append(1, '/');
    sbuf.append((const char*)this->rawdata._data + viaparam->version.start, viaparam->version.length);
    sbuf.append(1, '/');
    sbuf.append((const char*)this->rawdata._data + viaparam->transport.start, viaparam->transport.length);
    sbuf.append(1, ' ');
    sbuf.append((const char*)this->rawdata._data + viaparam->host.start, viaparam->host.length);
    if (viaparam->port.length)
    {
      sbuf.append(1, ':');
      sbuf.append((const char*)this->rawdata._data + viaparam->port.start, viaparam->port.length);
    }
    for (int i = 0; i < viaparam->num_params; i++)
    {
      sbuf.append(1, ';');
      sbuf.append((const char*)this->rawdata._data + viaparam->params[i].type.start, viaparam->params[i].type.length);
      if (viaparam->params[i].value.length)
      {
        sbuf.append(1, '=');
        sbuf.append((const char*)this->rawdata._data + viaparam->params[i].value.start, viaparam->params[i].value.length);
      }
    }
  }
  return sbuf;
}

int ViaHeader::GetHeaderValue(std::string& value)
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
  std::string sbuf;
  sbuf.reserve(length);
  for (int i = 0; i < this->num_via_parms; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      sbuf.append(1, ',');
    }
    via_param_t* viaparam = &this->via_parms[i];

    /* check for mandatory parts if exist */
    if (!(this->rawdata._length) || !(viaparam->protocol.length) ||
        !(viaparam->version.length) || !(viaparam->host.length))
    {
      return 1;
    }
    size_t length = (size_t)this->rawdata._length;
    value.reserve(length);
    value.append((const char*)this->rawdata._data + viaparam->protocol.start, viaparam->protocol.length);
    value.append(1, '/');
    value.append((const char*)this->rawdata._data + viaparam->version.start, viaparam->version.length);
    value.append(1, '/');
    value.append((const char*)this->rawdata._data + viaparam->transport.start, viaparam->transport.length);
    value.append(1, ' ');
    value.append((const char*)this->rawdata._data + viaparam->host.start, viaparam->host.length);
    if (viaparam->port.length)
    {
      value.append(1, ':');
      value.append((const char*)this->rawdata._data + viaparam->port.start, viaparam->port.length);
    }

    for (int i = 0; i < viaparam->num_params; i++)
    {
      value.append(1, ';');
      value.append((const char*)this->rawdata._data + viaparam->params[i].type.start, viaparam->params[i].type.length);
      if (viaparam->params[i].value.length)
      {
        value.append(1, '=');
        value.append((const char*)this->rawdata._data + viaparam->params[i].value.start, viaparam->params[i].value.length);
      }
    }
  }
  return 0;
}

/* provides the pointer to value part of the header in question.
   No any additional copy applied. */
int ViaHeader::GetHeaderValue(RawData& value)
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

void ViaHeader::PrintOut(std::ostringstream& buf)
{
  buf << "-------- Via Header DUMP [parsing-stat=" << this->parsing_stat << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
  if (this->parsing_stat != PARSED_SUCCESSFULLY)
  {
    buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
    return;
  }

  for (int i = 0; i < this->num_via_parms; i++)
  {
    if (i > 0)
    {
      /* multiple-header in a filed, add ',' */
      buf << ',';
    }
    via_param_t* viaparam = &this->via_parms[i];

    buf << "protocol    : " << std::string((const char*)this->rawdata._data + viaparam->protocol.start, viaparam->protocol.length) << std::endl;
    buf << "version     : " << std::string((const char*)this->rawdata._data + viaparam->version.start, viaparam->version.length) << std::endl;
    buf << "transport   : " << std::string((const char*)this->rawdata._data + viaparam->transport.start, viaparam->transport.length) << std::endl;
    buf << "sent-by-host: " << std::string((const char*)this->rawdata._data + viaparam->host.start, viaparam->host.length) << std::endl;
    buf << "sent-by-port: " << std::string((const char*)this->rawdata._data + viaparam->port.start, viaparam->port.length) << std::endl;

    if ((viaparam->branch.start <= 0) && (viaparam->branch.length <= 0))
    {
      for (int i = 0; i < viaparam->num_params; i++)
      {
        if (viaparam->params[i].type.length == 6)
        {
          int result = _strnicmp_((const char*)this->rawdata._data + viaparam->params[i].type.start, "branch", 6);
          if (result == 0)
          {
            viaparam->branch.start = viaparam->params[i].value.start;
            viaparam->branch.length = viaparam->params[i].value.length;
            break;
          }
        }
      }
    }
    buf << "branch      : " << std::string((const char*)this->rawdata._data + viaparam->branch.start, viaparam->branch.length) << std::endl;

    if (viaparam->num_params)
    {
      buf << "---------- Parameters ----------\n";
      for (int i = 0; i < viaparam->num_params; i++)
      {
        buf << std::string((const char*)this->rawdata._data + viaparam->params[i].type.start, viaparam->params[i].type.length);
        if (viaparam->params[i].value.length)
        {
          buf << '=';
          buf << std::string((const char*)this->rawdata._data + viaparam->params[i].value.start, viaparam->params[i].value.length);
          buf << std::endl;
        }
      }
    }
    buf << "----------------\n";
    buf << "Via: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
    buf << "---------------------------------------\n";
  }
}

