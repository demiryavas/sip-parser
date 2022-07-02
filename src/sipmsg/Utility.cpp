
#include "Utility.h"
#include "SipHeader.h"

enum param_parsing_state 
{ s_pp_dead
  , s_pp_space_before_param
  , s_pp_param_start
  , s_pp_param_start_lws
  , s_pp_param_name
  , s_pp_param_name_lws
  , s_pp_param_value_start
  , s_pp_param_value_start_lws
  , s_pp_param_value
  , s_pp_param_value_lws
  , s_pp_param_value_quoted
  , s_pp_param_value_quoted_end
  , s_pp_param_phase_completed
};

enum param_parsing_state parse_param_char(enum param_parsing_state s, const char ch, int* escaping)
{
  switch (s)
  {
    case s_pp_space_before_param:
      if (IS_LWS(ch)) {
        return s;
      }
      if (ch == ';') {
        /* skip ';' before begin */
        return s;
      }
      if (IS_PARAM_CHAR(ch))
      {
        return s_pp_param_start;
      }
      break;

    case s_pp_param_start:
    if (IS_LWS(ch))
    {
      return s_pp_param_start_lws;
    }
    if (IS_PARAM_CHAR(ch))
    {
      return s_pp_param_name;
    }
    break;

    case s_pp_param_start_lws:
      if (IS_LWS(ch))
      {
        return s_pp_param_start_lws;
      }
      if (IS_PARAM_CHAR(ch))
      {
        return s_pp_param_name;
      }
      break;

    case s_pp_param_name:
      if (IS_PARAM_CHAR(ch))
      {
        return s_pp_param_name;
      }
      if (IS_LWS(ch))
      {
        return s_pp_param_name_lws;
      }
      if (ch == '=')
      {
        return s_pp_param_value_start;
      }
      if (ch == ';')
      {
        return s_pp_param_start;
      }
      if (ch == ',')
      {
        return s_pp_param_phase_completed;
      }
      break;

    case s_pp_param_name_lws:
      if (IS_LWS(ch))
      {
        return s_pp_param_name_lws;
      }
      if (ch == '=')
      {
        return s_pp_param_value_start;
      }
      if (ch == ';')
      {
        return s_pp_param_start;
      }
      if (ch == ',')
      {
        return s_pp_param_phase_completed;
      }
      break;

    case s_pp_param_value_start:
      if (IS_PARAM_CHAR(ch))
      {
        return s_pp_param_value;
      }
      if (IS_LWS(ch))
      {
        return s_pp_param_value_start_lws;
      }
      if (ch == '"')
      {
        return s_pp_param_value_quoted;
      }
      break;

    case s_pp_param_value_start_lws:
      if (IS_LWS(ch))
      {
        return s_pp_param_value_start_lws;
      }
      if (IS_PARAM_CHAR(ch))
      {
        return s_pp_param_value;
      }
      if (ch == '"')
      {
        return s_pp_param_value_quoted;
      }
      break;

    case s_pp_param_value:
      if (IS_PARAM_CHAR(ch))
      {
        return s_pp_param_value;
      }
      if (IS_LWS(ch))
      {
        return s_pp_param_value_lws;
      }
      if (ch == ';')
      {
        return s_pp_param_start;
      }
      if (ch == ',')
      {
        return s_pp_param_phase_completed;
      }
      break;

    case s_pp_param_value_lws:
      if (IS_LWS(ch))
      {
        return s_pp_param_value_lws;
      }
      if (ch == ';')
      {
        return s_pp_param_start;
      }
      if (ch == ',')
      {
        return s_pp_param_phase_completed;
      }
      break;

    case s_pp_param_value_quoted:
      if (ch == '"')
      {
        if (*escaping > 0)
        {
          /* we have an escaped '"' char in param-value */
          *escaping = 0;
          return s;
        }
        return s_pp_param_value_quoted_end;
      }
      if (ch == '\\')
      {
        if (*escaping > 0)
        {
          /* we have an escaped '\' char in param-value */
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

    case s_pp_param_value_quoted_end:
      if (IS_LWS(ch))
      {
        return s_pp_param_value_lws;
      }
      if (ch == ';')
      {
        return s_pp_param_start;
      }
      if (ch == ',')
      {
        return s_pp_param_phase_completed;
      }
      break;

  }
  return s_pp_dead;
}

const char* parse_param_part(const char* buf, uint32_t pos, uint32_t buflen, param_pos_t* cparam, uint32_t maxnum_of_params, uint32_t* num_of_params, int* parse_error, int multihdr_allowed)
{
  int result = 0;
  /* TODO: Try to use s_pp_param_value_lws as a start-state */
  enum param_parsing_state s = s_pp_param_start; // s_pp_param_name_lws; // s_pp_space_before_param; // s_pp_param_start;
  enum param_parsing_state prev_s = s_pp_param_start; // s_pp_param_name_lws; // s_pp_space_before_param; // s_pp_param_start;
  const char* param_name_mark = NULL;
  const char* param_value_mark = NULL;
  param_pos_t* current_param = NULL;

  const char* p;
  int escaping = 0;

  if (buflen == 0) 
  {
    *parse_error = 2; /* TODO: use meaningful error codes */
    return buf;
  }
  *parse_error = 0;

  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_param_char(s, *p, &escaping);

    switch (s)
    {
      case s_pp_param_start:
        if (prev_s == s_pp_param_name)
        {
          current_param->type.start = param_name_mark - buf;
          current_param->type.length = p - param_name_mark;
        }
        else if (prev_s == s_pp_param_name_lws)
        {
          /* param name was set previously */
        }
        else if (prev_s == s_pp_param_value)
        {
          current_param->value.start = param_value_mark - buf;
          current_param->value.length = p - param_value_mark;
        }
        else if (prev_s == s_pp_param_value_quoted_end)
        {
          current_param->value.start = param_value_mark - buf;
          current_param->value.length = p - param_value_mark;
        }
        break;

      case s_pp_param_name:
        if ((prev_s == s_pp_param_start) || (prev_s == s_pp_param_start_lws))
        {
          param_name_mark = p;
          /* using '()' invokes default construtor which initializes
             the struct to 0*/
          current_param = &cparam[(*num_of_params)++];
        }
        break;

      case s_pp_param_name_lws:
        if (prev_s == s_pp_param_name)
        {
          current_param->type.start = param_name_mark - buf;
          current_param->type.length = p - param_name_mark;
        }
        break;

      case s_pp_param_value_start:
        if (prev_s == s_pp_param_name)
        {
          current_param->type.start = param_name_mark - buf;
          current_param->type.length = p - param_name_mark;
        }
        break;

      case s_pp_param_value:
      case s_pp_param_value_quoted:
        if ((prev_s == s_pp_param_value_start) || (prev_s == s_pp_param_value_start_lws))
        {
          param_value_mark = p;
        }
        break;

      case s_pp_param_value_lws:
        if ((prev_s == s_pp_param_value) || (prev_s == s_pp_param_value_quoted_end))
        {
          current_param->value.start = param_value_mark - buf;
          current_param->value.length = p - param_value_mark;
        }
        break;

      case s_pp_param_value_quoted_end:
        /* Nothing to do at the moment */
        break;

      case s_pp_param_phase_completed:
        if (multihdr_allowed)
        {
          if (prev_s == s_pp_param_name)
          {
            current_param->type.start = param_name_mark - buf;
            current_param->type.length = p - param_name_mark;
          }
          else if (prev_s == s_pp_param_name_lws)
          {
            /* param name was set previously */
          }
          else if (prev_s == s_pp_param_value)
          {
            current_param->value.start = param_value_mark - buf;
            current_param->value.length = p - param_value_mark;
          }
          else if (prev_s == s_pp_param_value_quoted_end)
          {
            current_param->value.start = param_value_mark - buf;
            current_param->value.length = p - param_value_mark;
          }
          /* special case that parameters are completed, we have to return */
          return p;
        }
        // else fall-through 

      case s_pp_dead:
        *parse_error = 3; /* TODO: assign meaningful error code */
        return p;

    } // switch (s)

    prev_s = s;
  } // for ()

  /* completed the buffer processing. Check for the current state to complete the job */
  switch (s)
  {
    case s_pp_param_name:
      current_param->type.start = param_name_mark - buf;
      current_param->type.length = p - param_name_mark;
      break;

    case s_pp_param_value:
      current_param->value.start = param_value_mark - buf;
      current_param->value.length = p - param_value_mark;
      break;

    case s_pp_param_value_quoted_end:
      current_param->value.start = param_value_mark - buf;
      current_param->value.length = p - param_value_mark;
      break;

    case s_pp_param_name_lws:
    case s_pp_param_value_lws:
      break;

    default:
      *parse_error = 4; /* TODO: assign meaningful error code */
      break;
  }
  return p;

}

int _strnicmp_(const char* s1, const char* s2, size_t n)
{
  if (n == 0)
  {
    return 0;
  }
  do
  {
    if (toupper(*s1) != toupper(*s2++))
    {
      return toupper(*(unsigned const char*)s1) - toupper(*(unsigned const char*)--s2);
    }
    if (*s1++ == 0)
    {
      break;
    }
  } while (--n != 0);

  return 0;
}


/*  When the header field value contains a display name, the URI
   including all URI parameters is enclosed in "<" and ">".  If no "<"
   and ">" are present, all parameters after the URI are header
   parameters, not URI parameters.  The display name can be tokens, or a
   quoted string, if a larger character set is desired.

   Even if the "display-name" is empty, the "name-addr" form MUST be
   used if the "addr-spec" contains a comma, semicolon, or question
   mark.  There may or may not be LWS between the display-name and the
   "<".
 */
enum naddr_parsing_state
{
  s_naddr_dead
  , s_naddr_spaces_before_value
  , s_naddr_display_name
  , s_naddr_display_name_lws
  , s_naddr_display_name_quoted
  , s_naddr_display_name_quoted_end
  , s_naddr_display_name_quoted_end_lws
  , s_naddr_url_start
  , s_naddr_url_collect
  , s_naddr_url_start_with_laquot
  , s_naddr_url_collect_aquoted
  , s_naddr_url_with_angle_quot
  , s_naddr_url_end_with_raquot
  , s_naddr_url_completed
};

enum naddr_parsing_state parse_naddr_char(enum naddr_parsing_state s, const char ch, int* escaping)
{
  switch (s)
  {
    case s_naddr_spaces_before_value:
      /* We consider all LWS has been skipped */
      if (ch == '"')
      {
        return s_naddr_display_name_quoted;
      }
      if (ch == '<')
      {
        return s_naddr_url_start_with_laquot;
      }
      if (IS_TOKEN(ch))
      {
        return s_naddr_display_name;
      }
      if (IS_LWS(ch))
      {
        return s;
      }
      break;

    case s_naddr_display_name:
      if (IS_TOKEN(ch))
      {
        return s_naddr_display_name;
      }
      if (IS_LWS(ch))
      {
        return s_naddr_display_name_lws;
      }
      if (ch == '<')
      {
        return s_naddr_url_start_with_laquot;
      }
      if ((ch == ':') || (ch == '/'))
      {
        /* Special case: no display name is included and URL part is not angle-quoted */
        return s_naddr_url_start;
      }
      break;

    case s_naddr_url_start:
      /* TODO: url-parser is needed to be invoked. There may be a need to skip LWS chars */
      return s_naddr_url_collect; // !!
      break;

    case s_naddr_url_collect:
      /* TODO: url-parser is needed to be invoked. There may be a need to skip LWS chars */
      if (IS_LWS(ch))
      {
        return s_naddr_url_completed;
      }
      if (ch == ';')
      {
        return s_naddr_url_completed;
      }
      return s_naddr_url_collect; // !!
      break;

    case s_naddr_display_name_lws:
      if (IS_LWS(ch))
      {
        return s;
      }
      if (ch == '<')
      {
        return s_naddr_url_start_with_laquot;
      }
      if (IS_TOKEN(ch))
      {
        /* Display name has spaces, so continue */
        return s_naddr_display_name;
      }
      break;

    case s_naddr_display_name_quoted:
      if (ch == '"')
      {
        if (*escaping > 0)
        {
          /* we have an escaped '"' char in display-name */
          *escaping = 0;
          return s;
        }
        return s_naddr_display_name_quoted_end;
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

    case s_naddr_display_name_quoted_end:
    case s_naddr_display_name_quoted_end_lws:
      if (IS_LWS(ch))
      {
        return s_naddr_display_name_quoted_end_lws;
      }
      if (ch == '<')
      {
        return s_naddr_url_start_with_laquot;
      }
      break;

    case s_naddr_url_start_with_laquot:
      /* TODO: We will collect all as an url until right-angle quote.
               Normally url-parser is needed to be invoked
               There may be a need to skip LWS chars */
      if (ch != '>')
      {
        return s_naddr_url_collect_aquoted;
      }
      break;

    case s_naddr_url_collect_aquoted:
      /* TODO: url-parser is needed to be invoked. There may be a need to skip LWS chars */
      if (ch == '>')
      {
        return s_naddr_url_end_with_raquot;
      }
      return s;
      break;

  }
  return s_naddr_dead;
}

const char* parse_name_addr_part(const char* buf, uint32_t pos, uint32_t buflen, str_pos_t* displayName, str_pos_t* url_str, int* parse_error, int multihdr_allowed)
{
  int result = 0;
  enum naddr_parsing_state s = s_naddr_spaces_before_value;
  enum naddr_parsing_state prev_s = s_naddr_spaces_before_value;
  const char* dispname_mark = NULL;
  const char* url_mark = NULL;

  bool re_parse = false;
  int escaping = 0;
  const char* p;

  if (buflen == 0)
  {
    *parse_error = 2; /* TODO: use meaningful error codes */
    return buf;
  }
  *parse_error = 0;

reparse:
  for (p = buf + pos; p < buf + buflen; p++)
  {
    s = parse_naddr_char(s, *p, &escaping);

    switch (s)
    {
      case s_naddr_display_name:
      case s_naddr_display_name_quoted:
        if (prev_s == s_naddr_spaces_before_value)
        {
          dispname_mark = p;
        }
        break;

      case s_naddr_display_name_lws:
        if (prev_s == s_naddr_display_name)
        {
          /* we may hit this position few times if display-name consists of spaces.
             The last hit will determine the actual display-name information*/
          displayName->start = dispname_mark - buf;
          displayName->length = p - dispname_mark;
        }
        break;

      case s_naddr_display_name_quoted_end_lws:
        if (prev_s == s_naddr_display_name_quoted_end)
        {
          displayName->start = dispname_mark - buf;
          displayName->length = p - dispname_mark;
        }
        break;

      case s_naddr_url_start:
        if (prev_s == s_naddr_display_name)
        {
          /* no display-name but URL without angle-quoted */
          re_parse = true;
          dispname_mark = NULL;
          prev_s = s_naddr_url_start;
          goto reparse;
        }
        break;

      case s_naddr_url_collect:
        if (prev_s == s_naddr_url_start)
        {
          url_mark = p;
        }
        break;

      case s_naddr_url_start_with_laquot:
        if ((prev_s == s_naddr_display_name) || (prev_s == s_naddr_display_name_quoted_end))
        {
          displayName->start = dispname_mark - buf;
          displayName->length = p - dispname_mark;
        }
        url_mark = p;
        break;

      case s_naddr_url_end_with_raquot:
        /* URL art is ended with '>', so consider that name-addr part is completed. */
        /* go one step furher to be able for correct calculation of length URL part */
        p++;
        url_str->start = url_mark - buf;
        url_str->length = p - url_mark;
        return p;

      case s_naddr_url_completed:
        if (prev_s == s_naddr_url_collect)
        {
          url_str->start = url_mark - buf;
          url_str->length = p - url_mark;
        }
        return p;
        break;

      case s_naddr_dead:
        *parse_error = 3; /* TODO: use meaningful error codes */
        return p;
    }
    prev_s = s;
  }

  /* completed the buffer processing. Check for the current state to complete the job */
  switch (s)
  {
    case s_naddr_url_end_with_raquot:
    case s_naddr_url_collect:
      url_str->start = url_mark - buf;
      url_str->length = p - url_mark;
      break;

    case s_naddr_url_completed:
      /* Nothing to set */
      break;

    default:
      result = 1;
      *parse_error = 4; /* TODO: use meaningful error codes */
      break;
  }
  return p;
}
