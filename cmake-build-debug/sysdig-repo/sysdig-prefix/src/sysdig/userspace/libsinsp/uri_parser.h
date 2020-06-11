/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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
#ifndef uri_parser_h
#define uri_parser_h
#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#if defined(_WIN32) && !defined(__MINGW32__) && \
  (!defined(_MSC_VER) || _MSC_VER<1600) && !defined(__WINE__)
#include <BaseTsd.h>
#include <stddef.h>
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

/* Compile with -DHTTP_PARSER_STRICT=0 to make less checks, but run
 * faster
 */
#ifndef HTTP_PARSER_STRICT
# define HTTP_PARSER_STRICT 1
#endif

/* Get an http_errno value from an http_parser */
#define HTTP_PARSER_ERRNO(p)            ((enum http_errno) (p)->http_errno)

enum http_parser_uri_fields
  { URI_FLD_SCHEMA           = 0
  , URI_FLD_HOST             = 1
  , URI_FLD_PORT             = 2
  , URI_FLD_PATH             = 3
  , URI_FLD_QUERY            = 4
  , URI_FLD_FRAGMENT         = 5
  , URI_FLD_USERINFO         = 6
  , URI_FLD_MAX              = 7
  };


/* Result structure for http_parser_parse_uri().
 *
 * Callers should index into field_data[] with UF_* values iff field_set
 * has the relevant (1 << UF_*) bit set. As a courtesy to clients (and
 * because we probably have padding left over), we convert any port to
 * a uint16_t.
 */
struct http_parser_uri {
  uint16_t field_set;           /* Bitmask of (1 << UF_*) values */
  uint16_t port;                /* Converted URI_FLD_PORT string */

  struct {
    uint16_t off;               /* Offset into buffer in which field starts */
    uint16_t len;               /* Length of run in buffer */
  } field_data[URI_FLD_MAX];
};


/* Initialize all http_parser_uri members to 0 */
void http_parser_uri_init(struct http_parser_uri *u);

/* Parse a URL; return nonzero on failure */
int http_parser_parse_uri(const char *buf, size_t buflen,
                          int is_connect,
                          struct http_parser_uri *u);

struct parsed_uri {
  const uint8_t error;
  const uint16_t field_set;
  const uint16_t scheme_start;
  const uint16_t scheme_end;
  const uint16_t user_info_start;
  const uint16_t user_info_end;
  const uint16_t host_start;
  const uint16_t host_end;
  const unsigned short port;
  const uint16_t path_start;
  const uint16_t path_end;
  const uint16_t query_start;
  const uint16_t query_end;
  const uint16_t fragment_start;
  const uint16_t fragment_end;
};

struct parsed_uri parse_uri(const char *uri_string);

#ifdef __cplusplus
}
#endif
#endif
