/* Based on src/http/ngx_http_parse.c from NGINX copyright Igor Sysoev
 *
 * Additional changes are licensed under the same terms as NGINX and
 * copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "uri_parser.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BIT_AT
# define BIT_AT(a, i)                                                \
  (!!((unsigned int) (a)[(unsigned int) (i) >> 3] &                  \
   (1 << ((unsigned int) (i) & 7))))
#endif

#if HTTP_PARSER_STRICT
# define T(v) 0
#else
# define T(v) v
#endif

static const uint8_t normal_url_char[32] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0    | T(2)   |   0    |   0    | T(16)  |   0    |   0    |   0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
        0    |   2    |   4    |   0    |   16   |   32   |   64   |  128,
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |   0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |   0, };

#undef T

enum state
  { s_dead = 1 /* important that this is > 0 */
  , s_req_spaces_before_url
  , s_req_schema
  , s_req_schema_slash
  , s_req_schema_slash_slash
  , s_req_server_start
  , s_req_server
  , s_req_server_with_at
  , s_req_path
  , s_req_query_string_start
  , s_req_query_string
  , s_req_fragment_start
  , s_req_fragment
  };

enum http_host_state
  {
    s_http_host_dead = 1
  , s_http_userinfo_start
  , s_http_userinfo
  , s_http_host_start
  , s_http_host_v6_start
  , s_http_host
  , s_http_host_v6
  , s_http_host_v6_end
  , s_http_host_v6_zone_start
  , s_http_host_v6_zone
  , s_http_host_port_start
  , s_http_host_port
};

/* Macros for character classes; depends on strict-mode  */
#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))
#define IS_HEX(c)           (IS_NUM(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
  (c) == ';' || (c) == ':' || (c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',')

#define STRICT_TOKEN(c)     (tokens[(unsigned char)c])

#if HTTP_PARSER_STRICT
#define TOKEN(c)            (tokens[(unsigned char)c])
#define IS_URL_CHAR(c)      (BIT_AT(normal_url_char, (unsigned char)c))
#define IS_HOST_CHAR(c)     (IS_ALPHANUM(c) || (c) == '.' || (c) == '-')
#else
#define TOKEN(c)            ((c == ' ') ? ' ' : tokens[(unsigned char)c])
#define IS_URL_CHAR(c)                                                         \
  (BIT_AT(normal_url_char, (unsigned char)c) || ((c) & 0x80))
#define IS_HOST_CHAR(c)                                                        \
  (IS_ALPHANUM(c) || (c) == '.' || (c) == '-' || (c) == '_')
#endif

#if HTTP_PARSER_STRICT
# define STRICT_CHECK(cond)                                          \
do {                                                                 \
  if (cond) {                                                        \
    SET_ERRNO(HPE_STRICT);                                           \
    goto error;                                                      \
  }                                                                  \
} while (0)
# define NEW_MESSAGE() (http_should_keep_alive(parser) ? start_state : s_dead)
#else
# define STRICT_CHECK(cond)
# define NEW_MESSAGE() start_state
#endif

/* Our URL parser.
 *
 * This is designed to be shared by http_parser_execute() for URL validation,
 * hence it has a state transition + byte-for-byte interface. In addition, it
 * is meant to be embedded in http_parser_parse_uri(), which does the dirty
 * work of turning state transitions URL components for its API.
 *
 * This function should only be invoked with non-space characters. It is
 * assumed that the caller cares about (and can detect) the transition between
 * URL and non-URL states by looking for these.
 */
static enum state
parse_url_char(enum state s, const char ch)
{
  if (ch == ' ' || ch == '\r' || ch == '\n') {
    return s_dead;
  }

#if HTTP_PARSER_STRICT
  if (ch == '\t' || ch == '\f') {
    return s_dead;
  }
#endif

  switch (s) {
    case s_req_spaces_before_url:
      /* Proxied requests are followed by scheme of an absolute URI (alpha).
       * All methods except CONNECT are followed by '/' or '*'.
       */

      if (ch == '/' || ch == '*') {
        return s_req_path;
      }

      if (IS_ALPHA(ch)) {
        return s_req_schema;
      }

      break;

    case s_req_schema:
      if (IS_ALPHA(ch)) {
        return s;
      }

      if (ch == ':') {
        return s_req_schema_slash;
      }

      break;

    case s_req_schema_slash:
      if (ch == '/') {
        return s_req_schema_slash_slash;
      }

      break;

    case s_req_schema_slash_slash:
      if (ch == '/') {
        return s_req_server_start;
      }

      break;

    case s_req_server_with_at:
      if (ch == '@') {
        return s_dead;
      }

    /* FALLTHROUGH */
    case s_req_server_start:
    case s_req_server:
      if (ch == '/') {
        return s_req_path;
      }

      if (ch == '?') {
        return s_req_query_string_start;
      }

      if (ch == '@') {
        return s_req_server_with_at;
      }

      if (IS_USERINFO_CHAR(ch) || ch == '[' || ch == ']') {
        return s_req_server;
      }

      break;

    case s_req_path:
      if (IS_URL_CHAR(ch)) {
        return s;
      }

      switch (ch) {
        case '?':
          return s_req_query_string_start;

        case '#':
          return s_req_fragment_start;
      }

      break;

    case s_req_query_string_start:
    case s_req_query_string:
      if (IS_URL_CHAR(ch)) {
        return s_req_query_string;
      }

      switch (ch) {
        case '?':
          /* allow extra '?' in query string */
          return s_req_query_string;

        case '#':
          return s_req_fragment_start;
      }

      break;

    case s_req_fragment_start:
      if (IS_URL_CHAR(ch)) {
        return s_req_fragment;
      }

      switch (ch) {
        case '?':
          return s_req_fragment;

        case '#':
          return s;
      }

      break;

    case s_req_fragment:
      if (IS_URL_CHAR(ch)) {
        return s;
      }

      switch (ch) {
        case '?':
        case '#':
          return s;
      }

      break;

    default:
      break;
  }

  /* We should never fall out of the switch above unless there's an error */
  return s_dead;
}

static enum http_host_state
http_parse_host_char(enum http_host_state s, const char ch) {
  switch(s) {
    case s_http_userinfo:
    case s_http_userinfo_start:
      if (ch == '@') {
        return s_http_host_start;
      }

      if (IS_USERINFO_CHAR(ch)) {
        return s_http_userinfo;
      }
      break;

    case s_http_host_start:
      if (ch == '[') {
        return s_http_host_v6_start;
      }

      if (IS_HOST_CHAR(ch)) {
        return s_http_host;
      }

      break;

    case s_http_host:
      if (IS_HOST_CHAR(ch)) {
        return s_http_host;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_end:
      if (ch == ':') {
        return s_http_host_port_start;
      }

      break;

    case s_http_host_v6:
      if (ch == ']') {
        return s_http_host_v6_end;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_start:
      if (IS_HEX(ch) || ch == ':' || ch == '.') {
        return s_http_host_v6;
      }

      if (s == s_http_host_v6 && ch == '%') {
        return s_http_host_v6_zone_start;
      }
      break;

    case s_http_host_v6_zone:
      if (ch == ']') {
        return s_http_host_v6_end;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_zone_start:
      /* RFC 6874 Zone ID consists of 1*( unreserved / pct-encoded) */
      if (IS_ALPHANUM(ch) || ch == '%' || ch == '.' || ch == '-' || ch == '_' ||
          ch == '~') {
        return s_http_host_v6_zone;
      }
      break;

    case s_http_host_port:
    case s_http_host_port_start:
      if (IS_NUM(ch)) {
        return s_http_host_port;
      }

      break;

    default:
      break;
  }
  return s_http_host_dead;
}

static int
http_parse_host(const char * buf, struct http_parser_uri *u, int found_at) {
  assert(u->field_set & (1 << URI_FLD_HOST));
  enum http_host_state s;

  const char *p;
  size_t buflen = u->field_data[URI_FLD_HOST].off + u->field_data[URI_FLD_HOST].len;

  u->field_data[URI_FLD_HOST].len = 0;

  s = found_at ? s_http_userinfo_start : s_http_host_start;

  for (p = buf + u->field_data[URI_FLD_HOST].off; p < buf + buflen; p++) {
    enum http_host_state new_s = http_parse_host_char(s, *p);

    if (new_s == s_http_host_dead) {
      return 1;
    }

    switch(new_s) {
      case s_http_host:
        if (s != s_http_host) {
          u->field_data[URI_FLD_HOST].off = p - buf;
        }
        u->field_data[URI_FLD_HOST].len++;
        break;

      case s_http_host_v6:
        if (s != s_http_host_v6) {
          u->field_data[URI_FLD_HOST].off = p - buf;
        }
        u->field_data[URI_FLD_HOST].len++;
        break;

      case s_http_host_v6_zone_start:
      case s_http_host_v6_zone:
        u->field_data[URI_FLD_HOST].len++;
        break;

      case s_http_host_port:
        if (s != s_http_host_port) {
          u->field_data[URI_FLD_PORT].off = p - buf;
          u->field_data[URI_FLD_PORT].len = 0;
          u->field_set |= (1 << URI_FLD_PORT);
        }
        u->field_data[URI_FLD_PORT].len++;
        break;

      case s_http_userinfo:
        if (s != s_http_userinfo) {
          u->field_data[URI_FLD_USERINFO].off = p - buf ;
          u->field_data[URI_FLD_USERINFO].len = 0;
          u->field_set |= (1 << URI_FLD_USERINFO);
        }
        u->field_data[URI_FLD_USERINFO].len++;
        break;

      default:
        break;
    }
    s = new_s;
  }

  /* Make sure we don't end somewhere unexpected */
  switch (s) {
    case s_http_host_start:
    case s_http_host_v6_start:
    case s_http_host_v6:
    case s_http_host_v6_zone_start:
    case s_http_host_v6_zone:
    case s_http_host_port_start:
    case s_http_userinfo:
    case s_http_userinfo_start:
      return 1;
    default:
      break;
  }

  return 0;
}

void
http_parser_uri_init(struct http_parser_uri *u) {
  memset(u, 0, sizeof(*u));
}

int
http_parser_parse_uri(const char *buf, size_t buflen, int is_connect,
                      struct http_parser_uri *u)
{
  enum state s;
  const char *p;
  enum http_parser_uri_fields uf, old_uf;
  int found_at = 0;

  u->port = u->field_set = 0;
  s = is_connect ? s_req_server_start : s_req_spaces_before_url;
  old_uf = URI_FLD_MAX;

  for (p = buf; p < buf + buflen; p++) {
    s = parse_url_char(s, *p);

    /* Figure out the next field that we're operating on */
    switch (s) {
      case s_dead:
        return 1;

      /* Skip delimiters */
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      case s_req_query_string_start:
      case s_req_fragment_start:
        continue;

      case s_req_schema:
        uf = URI_FLD_SCHEMA;
        break;

      case s_req_server_with_at:
        found_at = 1;

      /* FALLTROUGH */
      case s_req_server:
        uf = URI_FLD_HOST;
        break;

      case s_req_path:
        uf = URI_FLD_PATH;
        break;

      case s_req_query_string:
        uf = URI_FLD_QUERY;
        break;

      case s_req_fragment:
        uf = URI_FLD_FRAGMENT;
        break;

      default:
        assert(!"Unexpected state");
        return 1;
    }

    /* Nothing's changed; soldier on */
    if (uf == old_uf) {
      u->field_data[uf].len++;
      continue;
    }

    u->field_data[uf].off = p - buf;
    u->field_data[uf].len = 1;

    u->field_set |= (1 << uf);
    old_uf = uf;
  }

  /* host must be present if there is a schema */
  /* parsing http:///toto will fail */
  if ((u->field_set & (1 << URI_FLD_SCHEMA)) &&
      (u->field_set & (1 << URI_FLD_HOST)) == 0) {
    return 1;
  }

  if (u->field_set & (1 << URI_FLD_HOST)) {
    if (http_parse_host(buf, u, found_at) != 0) {
      return 1;
    }
  }

  /* CONNECT requests can only contain "hostname:port" */
  if (is_connect && u->field_set != ((1 << URI_FLD_HOST)|(1 << URI_FLD_PORT))) {
    return 1;
  }

  if (u->field_set & (1 << URI_FLD_PORT)) {
    /* Don't bother with endp; we've already validated the string */
    unsigned long v = strtoul(buf + u->field_data[URI_FLD_PORT].off, NULL, 10);

    /* Ports have a max value of 2^16 */
    if (v > 0xffff) {
      return 1;
    }

    u->port = (uint16_t) v;
  }

  return 0;
}

struct parsed_uri parse_uri(const char *uri_string) {
    struct http_parser_uri u;
    http_parser_uri_init(&u);

    int rc = http_parser_parse_uri(uri_string, strlen(uri_string), 0, &u);

    if (rc) {
        struct parsed_uri uri = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
        return uri;
    }

    struct parsed_uri uri = {
        0,
        u.field_set,
        u.field_data[0].off,
        u.field_data[0].off + u.field_data[0].len,
        u.field_data[6].off,
        u.field_data[6].off + u.field_data[6].len,
        u.field_data[1].off,
        u.field_data[1].off + u.field_data[1].len,
        u.port,
        u.field_data[3].off,
        u.field_data[3].off + u.field_data[3].len,
        u.field_data[4].off,
        u.field_data[4].off + u.field_data[4].len,
        u.field_data[5].off,
        u.field_data[5].off + u.field_data[5].len,
    };

    return uri;
}
