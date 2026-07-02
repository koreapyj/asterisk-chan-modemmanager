/*
 * ---------------------------------------------------------------------
 * Vendored from mmsd-tng (https://gitlab.com/kop316/mmsd)
 * Upstream file:   src/wsputil.h
 * Upstream commit: 341117141f8d30949fb1294cc71ee44af9b4c90f
 * Vendored on:     2026-07-02
 *
 * Local modifications (chan_modemmanager, src/mms/vendor/wsputil.h):
 *   - Added `#include <glib.h>`, `#include <time.h>` below. Upstream never
 *     includes these here because every upstream translation unit that
 *     uses this header always includes <glib.h> (and gets <time.h>
 *     transitively) earlier via mms.h. This vendor tree does not carry
 *     mms.h (see mmsutil.c's provenance note), so the header must be
 *     self-sufficient for the gboolean/time_t types it declares.
 *   - Wrapped the whole header in a `#ifndef CHAN_MM_MMS_VENDOR_WSPUTIL_H`
 *     include guard. Upstream has none (relying on this header being
 *     #include'd exactly once per translation unit); this codec's
 *     mms_codec.c needs both wsputil.h (directly, for
 *     wsp_decode_uintvar()/wsp_decode_content_type()) and mmsutil.h
 *     (via mms_codec.h), so a guard is needed to make double-inclusion
 *     safe.
 *   - No other changes; all declarations below are verbatim upstream.
 * ---------------------------------------------------------------------
 */

#ifndef CHAN_MM_MMS_VENDOR_WSPUTIL_H
#define CHAN_MM_MMS_VENDOR_WSPUTIL_H

/*
 *
 *  Multimedia Messaging Service Daemon - The Next Generation
 *
 *  Copyright (C) 2010-2011, Intel Corporation
 *                2021, Chris Talbot <chris@talbothome.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <glib.h>
#include <time.h>

enum wsp_header_iter_flag {
  WSP_HEADER_ITER_FLAG_REJECT_CP =                0x1,
  WSP_HEADER_ITER_FLAG_DETECT_MMS_MULTIPART =     0x2,
};

enum wsp_header_type {
  WSP_HEADER_TYPE_WELL_KNOWN,
  WSP_HEADER_TYPE_APPLICATION
};

enum wsp_value_type {
  WSP_VALUE_TYPE_LONG,
  WSP_VALUE_TYPE_SHORT,
  WSP_VALUE_TYPE_TEXT,
};

enum wsp_header_token {
  WSP_HEADER_TOKEN_APP_ID =       0x2F,
};

enum wsp_parameter_type {
  WSP_PARAMETER_TYPE_Q =                          0x00,
  WSP_PARAMETER_TYPE_CHARSET =                    0x01,
  WSP_PARAMETER_TYPE_LEVEL =                      0x02,
  WSP_PARAMETER_TYPE_TYPE =                       0x03,
  WSP_PARAMETER_TYPE_NAME_DEFUNCT =               0x05,
  WSP_PARAMETER_TYPE_FILENAME_DEFUNCT =           0x06,
  WSP_PARAMETER_TYPE_DIFFERENCES =                0x07,
  WSP_PARAMETER_TYPE_PADDING =                    0x08,
  WSP_PARAMETER_TYPE_CONTENT_TYPE =               0x09,
  WSP_PARAMETER_TYPE_START_DEFUNCT =              0x0A,
  WSP_PARAMETER_TYPE_START_INFO_DEFUNCT =         0x0B,
  WSP_PARAMETER_TYPE_COMMENT_DEFUNCT =            0x0C,
  WSP_PARAMETER_TYPE_DOMAIN_DEFUNCT =             0x0D,
  WSP_PARAMETER_TYPE_MAX_AGE =                    0x0E,
  WSP_PARAMETER_TYPE_PATH_DEFUNCT =               0x0F,
  WSP_PARAMETER_TYPE_SECURE =                     0x10,
  WSP_PARAMETER_TYPE_SEC =                        0x11,
  WSP_PARAMETER_TYPE_MAC =                        0x12,
  WSP_PARAMETER_TYPE_CREATION_DATE =              0x13,
  WSP_PARAMETER_TYPE_MODIFICATION_DATE =          0x14,
  WSP_PARAMETER_TYPE_READ_DATE =                  0x15,
  WSP_PARAMETER_TYPE_SIZE =                       0x16,
  WSP_PARAMETER_TYPE_NAME =                       0x17,
  WSP_PARAMETER_TYPE_FILENAME =                   0x18,
  WSP_PARAMETER_TYPE_START =                      0x19,
  WSP_PARAMETER_TYPE_START_INFO =                 0x1A,
  WSP_PARAMETER_TYPE_COMMENT =                    0x1B,
  WSP_PARAMETER_TYPE_DOMAIN =                     0x1C,
  WSP_PARAMETER_TYPE_PATH =                       0x1D,
  WSP_PARAMETER_TYPE_UNTYPED =                    0xFF,
};

enum wsp_parameter_value {
  WSP_PARAMETER_VALUE_TEXT,
  WSP_PARAMETER_VALUE_INT,
  WSP_PARAMETER_VALUE_DATE,
  WSP_PARAMETER_VALUE_Q,
};

struct wsp_parameter
{
  enum wsp_parameter_type type;
  enum wsp_parameter_value value;
  const char *untyped;
  union
  {
    const char *text;
    unsigned int integer;
    time_t date;
    float q;
  };
};

struct wsp_header_iter
{
  const unsigned char *pdu;
  unsigned int max;
  unsigned int pos;
  unsigned int flags;
  unsigned char code_page;

  enum wsp_header_type header_type;
  const void *header;

  enum wsp_value_type value_type;
  const void *value;

  unsigned int len;
};

struct wsp_multipart_iter
{
  const unsigned char *pdu;
  unsigned int max;
  unsigned int pos;

  const void *content_type;
  const void *headers;
  const void *body;

  unsigned int content_type_len;
  unsigned int headers_len;
  unsigned int body_len;
};

struct wsp_parameter_iter
{
  const unsigned char *pdu;
  unsigned int max;
  unsigned int pos;
};

#define MAX_TEXT_HEADER_SIZE 4096

struct wsp_text_header_iter
{
  char hdr[MAX_TEXT_HEADER_SIZE + 1];
  unsigned int pos;
  const char *key;
  const char *value;
};

gboolean wsp_decode_uintvar (const unsigned char *pdu,
                             unsigned int         len,
                             unsigned int        *out_len,
                             unsigned int        *consumed);
gboolean wsp_decode_integer (const unsigned char *pdu,
                             unsigned int         len,
                             unsigned int        *out_val,
                             unsigned int        *consumed);
gboolean wsp_decode_field (const unsigned char *pdu,
                           unsigned int         max,
                           enum wsp_value_type *out_type,
                           const void         **out_value,
                           unsigned int        *out_len,
                           unsigned int        *consumed);
gboolean wsp_get_well_known_content_type (const char   *text,
                                          unsigned int *out_val);
gboolean wsp_get_well_known_charset (const char   *text,
                                     unsigned int *out_val);
const char *wsp_decode_token_text (const unsigned char *pdu,
                                   unsigned int         len,
                                   unsigned int        *consumed);
const char *wsp_decode_text (const unsigned char *pdu,
                             unsigned int         len,
                             unsigned int        *consumed);
const char *wsp_decode_quoted_string (const unsigned char *pdu,
                                      unsigned int         len,
                                      unsigned int        *consumed);

gboolean wsp_decode_content_type (const unsigned char *pdu,
                                  unsigned int         max,
                                  const void         **out_value,
                                  unsigned int        *out_read,
                                  unsigned int        *out_param_len);
gboolean wsp_decode_application_id (struct wsp_header_iter *iter,
                                    const void            **out_value);

gboolean wsp_encode_uintvar (unsigned int   value,
                             unsigned char *dest,
                             unsigned int   dest_size,
                             unsigned int  *written);
gboolean wsp_encode_value_length (unsigned int   len,
                                  unsigned char *dest,
                                  unsigned int   dest_size,
                                  unsigned int  *written);
gboolean wsp_encode_integer (unsigned int   value,
                             unsigned char *dest,
                             unsigned int   dest_size,
                             unsigned int  *written);

void wsp_header_iter_init (struct wsp_header_iter *iter,
                           const unsigned char    *pdu,
                           unsigned int            len,
                           unsigned int            flags);
gboolean wsp_header_iter_next (struct wsp_header_iter *iter);
unsigned char wsp_header_iter_get_code_page (struct wsp_header_iter *iter);

gboolean wsp_header_iter_at_end (struct wsp_header_iter *iter);
gboolean wsp_header_iter_is_multipart (struct wsp_header_iter *iter);

enum wsp_header_type wsp_header_iter_get_hdr_type (struct wsp_header_iter *iter);
const unsigned char *wsp_header_iter_get_pdu (struct wsp_header_iter *iter);
const void *wsp_header_iter_get_hdr (struct wsp_header_iter *iter);
enum wsp_value_type wsp_header_iter_get_val_type (struct wsp_header_iter *iter);
const void *wsp_header_iter_get_val (struct wsp_header_iter *iter);
unsigned int wsp_header_iter_get_val_len (struct wsp_header_iter *iter);

gboolean wsp_multipart_iter_init (struct wsp_multipart_iter *mi,
                                  struct wsp_header_iter    *hi,
                                  const void               **out_content_type,
                                  unsigned int              *out_content_type_len);
gboolean wsp_multipart_iter_next (struct wsp_multipart_iter *mi);
const void *wsp_multipart_iter_get_content_type (struct wsp_multipart_iter *mi);
unsigned int wsp_multipart_iter_get_content_type_len (
  struct wsp_multipart_iter *mi);
const void *wsp_multipart_iter_get_hdr (struct wsp_multipart_iter *mi);
unsigned int wsp_multipart_iter_get_hdr_len (struct wsp_multipart_iter *mi);
const void *wsp_multipart_iter_get_body (struct wsp_multipart_iter *mi);
unsigned int wsp_multipart_iter_get_body_len (struct wsp_multipart_iter *mi);
gboolean wsp_multipart_iter_close (struct wsp_multipart_iter *mi,
                                   struct wsp_header_iter    *hi);

void wsp_parameter_iter_init (struct wsp_parameter_iter *pi,
                              const unsigned char       *pdu,
                              unsigned int               len);
gboolean wsp_parameter_iter_next (struct wsp_parameter_iter *pi,
                                  struct wsp_parameter      *out_param);

gboolean wsp_text_header_iter_init (struct wsp_text_header_iter *iter,
                                    const char                  *hdr);
gboolean wsp_text_header_iter_param_next (struct wsp_text_header_iter *iter);
const char *wsp_text_header_iter_get_key (struct wsp_text_header_iter *iter);
const char *wsp_text_header_iter_get_value (struct wsp_text_header_iter *iter);

#endif /* CHAN_MM_MMS_VENDOR_WSPUTIL_H */
