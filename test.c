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
 * FROM, OUT OF OR IN REDIRECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "http_parser.h"

static http_parser parser;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define MAX_HEADERS 13
#define MAX_ELEMENT_SIZE 2048
#define MAX_CHUNKS 16

struct message {
  const char *name; // for debugging purposes
  const char *raw;
  enum http_parser_type type;
  enum http_method method;
  int status_code;
  char response_status[MAX_ELEMENT_SIZE];
  char request_path[MAX_ELEMENT_SIZE];
  char request_url[MAX_ELEMENT_SIZE];
  char fragment[MAX_ELEMENT_SIZE];
  char query_string[MAX_ELEMENT_SIZE];
  char body[MAX_ELEMENT_SIZE];
  size_t body_size;
  const char *host;
  const char *userinfo;
  uint16_t port;
  int num_headers;
  enum { NONE=0, FIELD, VALUE } last_header_element;
  char headers [MAX_HEADERS][2][MAX_ELEMENT_SIZE];
  int should_keep_alive;

  int num_chunks;
  int num_chunks_complete;
  int chunk_lengths[MAX_CHUNKS];

  const char *upgrade; // upgraded body

  unsigned short http_major;
  unsigned short http_minor;

  int message_begin_cb_called;
  int headers_complete_cb_called;
  int message_complete_cb_called;
  int status_cb_called;
  int message_complete_on_eof;
  int body_is_final;
};

struct message messages[5];
int num_messages;
int currently_parsing_eof;

const struct message requests[] =
#define STANDART_OPTIONS 0
{ {.name= "vlc options"
  ,.type= HTTP_REQUEST
  ,.raw= "OPTIONS rtsp://192.168.1.101/live RTSP/1.0\r\n"
         "CSeq: 1\r\n"
         "User-Agent: VLC media player (LIVE555 Streaming Media v2005.11.10)\r\n"
         "\r\n"
  ,.should_keep_alive = 1
  ,.message_complete_on_eof = 0
  ,.http_major = 1
  ,.http_minor = 0
  ,.method = HTTP_OPTIONS
  ,.query_string = ""
  ,.fragment = ""
  ,.request_path= "/live"
  ,.request_url = "rtsp://192.168.1.101/live"
  ,.num_headers= 2
  ,.headers=
    { { "CSeq", "1" }
    , { "User-Agent", "VLC media player (LIVE555 Streaming Media v2005.11.10)" }
    }
  ,.body= ""
  },

#define STANDART_DESCRIBE 1
 {.name= "vlc describe"
  ,.type= HTTP_REQUEST
  ,.raw= "DESCRIBE rtsp://192.168.1.101/live RTSP/1.0\r\n"
         "CSeq: 2\r\n"
         "Accept: application/sdp\r\n"
         "User-Agent: VLC media player (LIVE555 Streaming Media v2005.11.10)\r\n"
         "\r\n"
  ,.should_keep_alive = 1
  ,.message_complete_on_eof = 0
  ,.http_major = 1
  ,.http_minor = 0
  ,.method = HTTP_DESCRIBE
  ,.query_string = ""
  ,.fragment = ""
  ,.request_path= "/live"
  ,.request_url = "rtsp://192.168.1.101/live"
  ,.num_headers= 3
  ,.headers=
    { { "CSeq", "2" }
    , { "Accept", "application/sdp" }
    , { "User-Agent", "VLC media player (LIVE555 Streaming Media v2005.11.10)" }
    }
  ,.body= ""
  }
};

size_t
strnlen(const char *s, size_t maxlen)
{
  const char *p;

  p = memchr(s, '\0', maxlen);
  if (p == NULL)
    return maxlen;

  return p - s;
}

size_t
strlncat(char *dst, size_t len, const char *src, size_t n)
{
  size_t slen;
  size_t dlen;
  size_t rlen;
  size_t ncpy;

  slen = strnlen(src, n);
  dlen = strnlen(dst, len);

  if (dlen < len) {
    rlen = len - dlen;
    ncpy = slen < rlen ? slen : (rlen - 1);
    memcpy(dst + dlen, src, ncpy);
    dst[dlen + ncpy] = '\0';
  }

  assert(len > slen + dlen);
  return slen + dlen;
}

size_t
strlncpy(char *dst, size_t len, const char *src, size_t n)
{
  size_t slen;
  size_t ncpy;

  slen = strnlen(src, n);

  if (len > 0) {
    ncpy = slen < len ? slen : (len - 1);
    memcpy(dst, src, ncpy);
    dst[ncpy] = '\0';
  }

  assert(len > slen);
  return slen;
}

static void
print_error (const char *raw, size_t error_location)
{
  fprintf(stderr, "\n*** %s ***\n\n",
          http_errno_description(HTTP_PARSER_ERRNO(&parser)));

  int this_line = 0, char_len = 0;
  size_t i, j, len = strlen(raw), error_location_line = 0;
  for (i = 0; i < len; i++) {
    if (i == error_location) this_line = 1;
    switch (raw[i]) {
      case '\r':
        char_len = 2;
        fprintf(stderr, "\\r");
        break;

      case '\n':
        fprintf(stderr, "\\n\n");

        if (this_line) goto print;

        error_location_line = 0;
        continue;

      default:
        char_len = 1;
        fputc(raw[i], stderr);
        break;
    }
    if (!this_line) error_location_line += char_len;
  }

  fprintf(stderr, "[eof]\n");

 print:
  for (j = 0; j < error_location_line; j++) {
    fputc(' ', stderr);
  }
  fprintf(stderr, "^\n\nerror location: %u\n", (unsigned int)error_location);
}


int
request_url_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == &parser);
  strlncat(messages[num_messages].request_url,
           sizeof(messages[num_messages].request_url),
           buf,
           len);
  return 0;
}

int
header_field_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == &parser);
  struct message *m = &messages[num_messages];
  if (m->last_header_element != FIELD)
    m->num_headers++;

  strlncat(m->headers[m->num_headers-1][0],
           sizeof(m->headers[m->num_headers-1][0]),
           buf,
           len);

  m->last_header_element = FIELD;

  return 0;
}

int
header_value_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == &parser);
  struct message *m = &messages[num_messages];
  strlncat(m->headers[m->num_headers-1][1],
           sizeof(m->headers[m->num_headers-1][1]),
           buf,
           len);

  m->last_header_element = VALUE;

  return 0;
}

void
check_body_is_final (const http_parser *p)
{
  if (messages[num_messages].body_is_final) {
    fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                    "on last on_body callback call "
                    "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }
  messages[num_messages].body_is_final = http_body_is_final(p);
}

int
body_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == &parser);
  strlncat(messages[num_messages].body,
           sizeof(messages[num_messages].body),
           buf,
           len);
  messages[num_messages].body_size += len;
  check_body_is_final(p);
 // printf("body_cb: '%s'\n", requests[num_messages].body);
  return 0;
}

int
count_body_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == &parser);
  assert(buf);
  messages[num_messages].body_size += len;
  check_body_is_final(p);
  return 0;
}

int
message_begin_cb (http_parser *p)
{
  assert(p == &parser);
  assert(!messages[num_messages].message_begin_cb_called);
  messages[num_messages].message_begin_cb_called = TRUE;
  return 0;
}

int
headers_complete_cb (http_parser *p)
{
  assert(p == &parser);
  messages[num_messages].method = parser.method;
  messages[num_messages].status_code = parser.status_code;
  messages[num_messages].http_major = parser.http_major;
  messages[num_messages].http_minor = parser.http_minor;
  messages[num_messages].headers_complete_cb_called = TRUE;
  messages[num_messages].should_keep_alive = http_should_keep_alive(&parser);
  return 0;
}

int
message_complete_cb (http_parser *p)
{
  assert(p == &parser);
  if (messages[num_messages].should_keep_alive !=
      http_should_keep_alive(&parser))
  {
    fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
                    "value in both on_message_complete and on_headers_complete "
                    "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }

  if (messages[num_messages].body_size &&
      http_body_is_final(p) &&
      !messages[num_messages].body_is_final)
  {
    fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                    "on last on_body callback call "
                    "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }

  messages[num_messages].message_complete_cb_called = TRUE;

  messages[num_messages].message_complete_on_eof = currently_parsing_eof;

  num_messages++;
  return 0;
}

int
response_status_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == &parser);

  messages[num_messages].status_cb_called = TRUE;

  strlncat(messages[num_messages].response_status,
           sizeof(messages[num_messages].response_status),
           buf,
           len);
  return 0;
}

int
chunk_header_cb (http_parser *p)
{
  assert(p == &parser);
  int chunk_idx = messages[num_messages].num_chunks;
  messages[num_messages].num_chunks++;
  if (chunk_idx < MAX_CHUNKS) {
    messages[num_messages].chunk_lengths[chunk_idx] = p->content_length;
  }

  return 0;
}

int
chunk_complete_cb (http_parser *p)
{
  assert(p == &parser);

  /* Here we want to verify that each chunk_header_cb is matched by a
   * chunk_complete_cb, so not only should the total number of calls to
   * both callbacks be the same, but they also should be interleaved
   * properly */
  assert(messages[num_messages].num_chunks ==
         messages[num_messages].num_chunks_complete + 1);

  messages[num_messages].num_chunks_complete++;
  return 0;
}

static http_parser_settings settings ={
  .on_message_begin = message_begin_cb
  ,.on_header_field = header_field_cb
  ,.on_header_value = header_value_cb
  ,.on_url = request_url_cb
  ,.on_status = response_status_cb
  ,.on_body = body_cb
  ,.on_headers_complete = headers_complete_cb
  ,.on_message_complete = message_complete_cb
  ,.on_chunk_header = chunk_header_cb
  ,.on_chunk_complete = chunk_complete_cb
};

static inline int
check_str_eq (const struct message *m,
              const char *prop,
              const char *expected,
              const char *found) {
  if ((expected == NULL) != (found == NULL)) {
    printf("\n*** Error: %s in '%s' ***\n\n", prop, m->name);
    printf("expected %s\n", (expected == NULL) ? "NULL" : expected);
    printf("   found %s\n", (found == NULL) ? "NULL" : found);
    return 0;
  }
  if (expected != NULL && 0 != strcmp(expected, found)) {
    printf("\n*** Error: %s in '%s' ***\n\n", prop, m->name);
    printf("expected '%s'\n", expected);
    printf("   found '%s'\n", found);
    return 0;
  }
  return 1;
}

static inline int
check_num_eq (const struct message *m,
              const char *prop,
              int expected,
              int found) {
  if (expected != found) {
    printf("\n*** Error: %s in '%s' ***\n\n", prop, m->name);
    printf("expected %d\n", expected);
    printf("   found %d\n", found);
    return 0;
  }
  return 1;
}

#define MESSAGE_CHECK_STR_EQ(expected, found, prop) \
  if (!check_str_eq(expected, #prop, expected->prop, found->prop)) return 0

#define MESSAGE_CHECK_NUM_EQ(expected, found, prop) \
  if (!check_num_eq(expected, #prop, expected->prop, found->prop)) return 0

#define MESSAGE_CHECK_URL_EQ(u, expected, found, prop, fn)           \
do {                                                                 \
  char ubuf[256];                                                    \
                                                                     \
  if ((u)->field_set & (1 << (fn))) {                                \
    memcpy(ubuf, (found)->request_url + (u)->field_data[(fn)].off,   \
      (u)->field_data[(fn)].len);                                    \
    ubuf[(u)->field_data[(fn)].len] = '\0';                          \
  } else {                                                           \
    ubuf[0] = '\0';                                                  \
  }                                                                  \
                                                                     \
  check_str_eq(expected, #prop, expected->prop, ubuf);               \
} while(0)

int
message_eq (int index, const struct message *expected)
{
  int i;
  struct message *m = &messages[index];

  MESSAGE_CHECK_NUM_EQ(expected, m, http_major);
  MESSAGE_CHECK_NUM_EQ(expected, m, http_minor);

  if (expected->type == HTTP_REQUEST) {
    MESSAGE_CHECK_NUM_EQ(expected, m, method);
  } else {
    MESSAGE_CHECK_NUM_EQ(expected, m, status_code);
    MESSAGE_CHECK_STR_EQ(expected, m, response_status);
    assert(m->status_cb_called);
  }

  assert(m->message_begin_cb_called);
  assert(m->headers_complete_cb_called);
  assert(m->message_complete_cb_called);


  MESSAGE_CHECK_STR_EQ(expected, m, request_url);

  // RTPS DOES NOT HAVE CONNECT

  if (expected->body_size) {
    MESSAGE_CHECK_NUM_EQ(expected, m, body_size);
  } else {
    MESSAGE_CHECK_STR_EQ(expected, m, body);
  }

  {
    assert(m->num_chunks == m->num_chunks_complete);
    MESSAGE_CHECK_NUM_EQ(expected, m, num_chunks_complete);
    for (i = 0; i < m->num_chunks && i < MAX_CHUNKS; i++) {
      MESSAGE_CHECK_NUM_EQ(expected, m, chunk_lengths[i]);
    }
  }

  MESSAGE_CHECK_NUM_EQ(expected, m, num_headers);

  int r;
  for (i = 0; i < m->num_headers; i++) {
    r = check_str_eq(expected, "header field", expected->headers[i][0], m->headers[i][0]);
    if (!r) return 0;
    r = check_str_eq(expected, "header value", expected->headers[i][1], m->headers[i][1]);
    if (!r) return 0;
  }

  return 1;
}

void parser_init (enum http_parser_type type) {
  num_messages = 0;
  http_parser_init(&parser, type);
  memset(&messages, 0, sizeof messages);
}

size_t parse (const char *buf, size_t len) {
  size_t nparsed;
  currently_parsing_eof = (len == 0);
  nparsed = http_parser_execute(&parser, &settings, buf, len);
  return nparsed;
}

void test_message(const struct message *message) {
  size_t raw_len = strlen(message->raw);
  size_t msg1len;

  for (msg1len = 0; msg1len < raw_len; msg1len++) {
    size_t read;
    const char *msg1 = message->raw;
    const char *msg2 = msg1 + msg1len;
    size_t msg2len = raw_len - msg1len;
    
    parser_init(message->type);

    if (msg1len) {
      assert(num_messages == 0);
      messages[0].headers_complete_cb_called = FALSE;

      read = parse(msg1, msg1len);

      if (!messages[0].headers_complete_cb_called && parser.nread != read) {
        assert(parser.nread == read);
        print_error(msg1, read);
        abort();
      }

      if (read != msg1len) {
        print_error(msg1, read);
        abort();
      }
    } // msg1len > 0

    read = parse(msg2, msg2len);
    if (read != msg2len) {
      print_error(msg2, read);
      abort();
    }

    read = parse(NULL, 0);
    if (read != 0) {
      print_error(message->raw, read);
      abort();
    }

    if (num_messages != 1) {
      printf("\n*** num_messages != 1 after testing '%s' ***\n\n", message->name);
      abort();
    }

    if(!message_eq(0, message)) abort();
  } // for loop
}

int main(void) {
  size_t i;

  for (i = 0; i < ARRAY_SIZE(requests); i++) {
    test_message(&requests[i]);
  }

  return 0;
}