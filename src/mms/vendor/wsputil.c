/*
 * ---------------------------------------------------------------------
 * Vendored from mmsd-tng (https://gitlab.com/kop316/mmsd)
 * Upstream file:   src/wsputil.c
 * Upstream commit: 341117141f8d30949fb1294cc71ee44af9b4c90f
 * Vendored on:     2026-07-02
 *
 * Local modifications (chan_modemmanager, src/mms/vendor/wsputil.c):
 *   - None. This file is vendored verbatim (byte-for-byte identical to
 *     the upstream commit above, only this provenance block was added).
 *     The upstream copyright/license header immediately below is kept
 *     intact.
 * ---------------------------------------------------------------------
 */

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib.h>

#include "wsputil.h"

struct wsp_hex_str_entry
{
  unsigned int type;
  const char *type_str;
};

/*
 * http://www.wapforum.org/wina/wsp-content-type.htm
 */
static const char *content_types[] = {
  "*/*",
  "text/*",
  "text/html",
  "text/plain",
  "text/x-hdml",
  "text/x-ttml",
  "text/x-vCalendar",
  "text/x-vCard",
  "text/vnd.wap.wml",
  "text/vnd.wap.wmlscript",
  "text/vnd.wap.wta-event",
  "multipart/*",
  "multipart/mixed",
  "multipart/form-data",
  "multipart/byterantes",
  "multipart/alternative",
  "application/*",
  "application/java-vm",
  "application/x-www-form-urlencoded",
  "application/x-hdmlc",
  "application/vnd.wap.wmlc",
  "application/vnd.wap.wmlscriptc",
  "application/vnd.wap.wta-eventc",
  "application/vnd.wap.uaprof",
  "application/vnd.wap.wtls-ca-certificate",
  "application/vnd.wap.wtls-user-certificate",
  "application/x-x509-ca-cert",
  "application/x-x509-user-cert",
  "image/*",
  "image/gif",
  "image/jpeg",
  "image/tiff",
  "image/png",
  "image/vnd.wap.wbmp",
  "application/vnd.wap.multipart.*",
  "application/vnd.wap.multipart.mixed",
  "application/vnd.wap.multipart.form-data",
  "application/vnd.wap.multipart.byteranges",
  "application/vnd.wap.multipart.alternative",
  "application/xml",
  "text/xml",
  "application/vnd.wap.wbxml",
  "application/x-x968-cross-cert",
  "application/x-x968-ca-cert",
  "application/x-x968-user-cert",
  "text/vnd.wap.si",
  "application/vnd.wap.sic",
  "text/vnd.wap.sl",
  "application/vnd.wap.slc",
  "text/vnd.wap.co",
  "application/vnd.wap.coc",
  "application/vnd.wap.multipart.related",
  "application/vnd.wap.sia",
  "text/vnd.wap.connectivity-xml",
  "application/vnd.wap.connectivity-wbxml",
  "application/pkcs7-mime",
  "application/vnd.wap.hashed-certificate",
  "application/vnd.wap.signed-certificate",
  "application/vnd.wap.cert-response",
  "application/xhtml+xml",
  "application/wml+xml",
  "text/css",
  "application/vnd.wap.mms-message",
  "application/vnd.wap.rollover-certificate",
  "application/vnd.wap.locc+wbxml",
  "application/vnd.wap.loc+xml",
  "application/vnd.syncml.dm+wbxml",
  "application/vnd.syncml.dm+xml",
  "application/vnd.syncml.notification",
  "application/vnd.wap.xhtml+xml",
  "application/vnd.wv.csp.cir",
  "application/vnd.oma.dd+xml",
  "application/vnd.oma.drm.message",
  "application/vnd.oma.drm.content",
  "application/vnd.oma.drm.rights+xml",
  "application/vnd.oma.drm.rights+wbxml",
};

#define LAST_CONTENT_TYPE (sizeof(content_types) / sizeof(const char *))

/*
 * http://www.wapforum.org/wina/push-app-id.htm
 */
static const struct wsp_hex_str_entry app_id[] = {
  { 0x04, "x-wap-application:mms.ua" },
  { 0x07, "x-wap-application:syncml.dm" },
  { 0x08, "x-wap-application:drm.ua" },
  { 0xFF, NULL }
};

/* http://www.wapforum.org/wina/wsp-content-type.htm */
static const struct wsp_hex_str_entry extension_mimetypes[] = {
  { 0x0201, "application/vnd.uplanet.cacheop-wbxml" },
  { 0x0202, "application/vnd.uplanet.signal" },
  { 0x0203, "application/vnd.uplanet.alert-wbxml" },
  { 0x0204, "application/vnd.uplanet.list-wbxml" },
  { 0x0205, "application/vnd.uplanet.listcmd-wbxml" },
  { 0x0206, "application/vnd.uplanet.channel-wbxml" },
  { 0x0207, "application/vnd.uplanet.provisioning-status-uri" },
  { 0x0208, "x-wap.multipart/vnd.uplanet.header-set" },
  { 0x0209, "application/vnd.uplanet.bearer-choice-wbxml" },
  { 0x020A, "application/vnd.phonecom.mmc-wbxml" },
  { 0x020B, "application/vnd.nokia.syncset+wbxml" },
  { 0x020C, "image/x-up-wpng" },
  { 0xFFFF, NULL },
};

static const struct wsp_hex_str_entry charset_assignments[] = {
  { 0x0000, "*" },
  { 0x07EA, "big5" },
  { 0x03E8, "iso-10646-ucs-2" },
  { 0x0004, "iso-8859-1" },
  { 0x0005, "iso-8859-2" },
  { 0x0006, "iso-8859-3" },
  { 0x0007, "iso-8859-4" },
  { 0x0008, "iso-8859-5" },
  { 0x0009, "iso-8859-6" },
  { 0x000A, "iso-8859-7" },
  { 0x000B, "iso-8859-8" },
  { 0x000C, "iso-8859-9" },
  { 0x0011, "shift_JIS" },
  { 0x0003, "us-ascii" },
  { 0x006A, "utf-8" },
  { 0x03F7, "utf-16" },
  { 0xFFFF, NULL },
};

/*
 * Control Characters 0-8, 10-31 and 127.  The tab character is omitted
 * since it is included in the sep chars array and the most generic TEXT
 * type of RFC 2616 explicitly allows tabs
 */
static const char *ctl_chars = "\x01\x02\x03\x04\x05\x06\x07\x08\x0A"
                               "\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14"
                               "\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E"
                               "\x1F\x7F";

static const char *sep_chars = "()<>@,;:\\\"/[]?={} \t";

static const char *
decode_text_common (const unsigned char *pdu,
                    unsigned int         len,
                    gboolean             filter_ctl,
                    gboolean             filter_sep,
                    unsigned int        *consumed)
{
  unsigned char *c;

  c = memchr (pdu, '\0', len);

  if (c == NULL)
    g_warning ("c is NULL!");

  /* RFC 2616 Section 2.2 */
  if (filter_ctl && strpbrk ((const char *) pdu, ctl_chars) != NULL)
    return NULL;

  if (filter_sep && strpbrk ((const char *) pdu, sep_chars) != NULL)
    return NULL;

  if (consumed)
    {
      if (c == NULL)
        return NULL;

      c += 1;

      *consumed = c - pdu;
    }

  return (const char *) pdu;
}

const char *
wsp_decode_token_text (const unsigned char *pdu,
                       unsigned int         len,
                       unsigned int        *consumed)
{
  return decode_text_common (pdu, len, TRUE, TRUE, consumed);
}

const char *
wsp_decode_text (const unsigned char *pdu,
                 unsigned int         len,
                 unsigned int        *consumed)
{
  const char *r;
  unsigned int fudge = 0;

  if (*pdu == 127)
    {
      pdu++;

      /*
       * This was in the original mmsd code, but I found an edge case where this breaks decoding a message. Section section
       *  8.4.2.1 of Wap Forum/Open Mobile Alliance, "WAP-230 Wireless Session Protocol Specification"
       * http://www.openmobilealliance.org/tech/affiliates/LicenseAgreement.asp?DocName=/wap/wap-230-wsp-20010705-a.pdf
       * says that 
       * Text-string = [Quote] *TEXT End-of-string
       * If the first character in the TEXT is in the range of 128-255, a Quote character must precede it.
       * Otherwise the Quote character must be omitted. The Quote is not part of the contents.
       *
       * Technically this is correct, but being to strict about it doesn't make a lot of sense. Instead,
       * let's just emit a message for it.
       *
       * if (*pdu < 128)
       *   return NULL;
       */

      if (*pdu < 128)
        g_message ("Warning: PDU Decode test less than 128!");

      len -= 1;
      fudge += 1;
    }

  r = decode_text_common (pdu, len, TRUE, FALSE, consumed);

  if (consumed)
    *consumed += fudge;

  return r;
}

const char *
wsp_decode_quoted_string (const unsigned char *pdu,
                          unsigned int         len,
                          unsigned int        *consumed)
{
  const char *text;

  text = wsp_decode_text (pdu, len, consumed);
  if (text == NULL)
    return NULL;

  if (*text != '"')
    return NULL;

  /* Skip initial quote */
  text++;

  return text;
}

gboolean
wsp_decode_uintvar (const unsigned char *pdu,
                    unsigned int         len,
                    unsigned int        *out_len,
                    unsigned int        *consumed)
{
  unsigned int var;
  unsigned int i;
  unsigned int cont;

  for (i = 0, var = 0, cont = TRUE; i < 5 && i < len && cont; i++)
    {
      cont = pdu[i] & 0x80;
      var = (var << 7) | (pdu[i] & 0x7f);
    }

  if (cont)
    return FALSE;

  if (out_len)
    *out_len = var;

  if (consumed)
    *consumed = i;

  return TRUE;
}

gboolean
wsp_decode_integer (const unsigned char *pdu,
                    unsigned int         len,
                    unsigned int        *out_val,
                    unsigned int        *consumed)
{
  unsigned int var;
  unsigned int i;
  unsigned int count;

  if (pdu[0] & 0x80)
    {
      var = pdu[0] & 0x7f;
      count = 1;
    }
  else if (pdu[0] <= 30)
    {
      unsigned int value_len = *pdu;
      if (value_len > (len - 1))
        return FALSE;

      if (value_len > sizeof(unsigned int))
        return FALSE;

      var = 0;
      for (i = 0; i < value_len; i++)
        var = (var << 8) | pdu[i + 1];
      count = value_len + 1;
    }
  else
    return FALSE;

  if (out_val)
    *out_val = var;

  if (consumed)
    *consumed = count;

  return TRUE;
}

gboolean
wsp_decode_field (const unsigned char *pdu,
                  unsigned int         max,
                  enum wsp_value_type *out_type,
                  const void         **out_value,
                  unsigned int        *out_len,
                  unsigned int        *out_read)
{
  const unsigned char *end = pdu + max;
  const unsigned char *begin = pdu;
  unsigned int len;
  enum wsp_value_type value;
  unsigned int consumed;

  if (*pdu <= 30)
    {
      len = *pdu;
      pdu++;

      if (pdu + len > end)
        return FALSE;

      value = WSP_VALUE_TYPE_LONG;
    }
  else if (*pdu >= 128)
    {
      len = 1;
      value = WSP_VALUE_TYPE_SHORT;
    }
  else if (*pdu == 31)
    {
      pdu++;

      if (pdu == end)
        return FALSE;

      if (wsp_decode_uintvar (pdu, end - pdu,
                              &len, &consumed) == FALSE)
        return FALSE;

      pdu += consumed;

      if (pdu + len > end)
        return FALSE;

      value = WSP_VALUE_TYPE_LONG;
    }
  else {
      if (decode_text_common (pdu, end - pdu,
                              TRUE, FALSE, &len) == NULL)
        return FALSE;

      value = WSP_VALUE_TYPE_TEXT;
    }

  if (out_type)
    *out_type = value;

  if (out_value)
    *out_value = pdu;

  if (out_len)
    *out_len = len;

  if (out_read)
    *out_read = pdu - begin + len;

  return TRUE;
}

gboolean
wsp_get_well_known_content_type (const char   *text,
                                 unsigned int *out_val)
{
  unsigned int i;

  for (i = 0; i < LAST_CONTENT_TYPE; i++)
    if (g_str_equal (text, content_types[i]) == TRUE)
      {
        *out_val = i;
        return TRUE;
      }

  return FALSE;
}

gboolean
wsp_get_well_known_charset (const char   *text,
                            unsigned int *out_val)
{
  unsigned int i;

  for (i = 0; charset_assignments[i].type_str != NULL; i++)
    if (g_str_equal (charset_assignments[i].type_str,
                     text) == TRUE)
      {
        *out_val = charset_assignments[i].type;
        return TRUE;
      }

  return FALSE;
}

static const char *
get_text_entry (unsigned int                    value,
                const struct wsp_hex_str_entry *table)
{
  unsigned int i;

  for (i = 0; table[i].type_str != NULL; i++)
    if (table[i].type == value)
      return table[i].type_str;

  return NULL;
}

gboolean
wsp_decode_content_type (const unsigned char *pdu,
                         unsigned int         max,
                         const void         **out_value,
                         unsigned int        *out_read,
                         unsigned int        *out_param_len)
{
  unsigned int param_len = 0;
  unsigned int len;
  const void *data;
  enum wsp_value_type value_type;
  unsigned int consumed;

  if (wsp_decode_field (pdu, max, &value_type, &data,
                        &len, &consumed) != TRUE)
    return FALSE;

  if (value_type == WSP_VALUE_TYPE_LONG)
    {
      unsigned int media_len;
      unsigned int value_len;

      if (wsp_decode_field (data, max, &value_type, &data,
                            &value_len, &media_len) != TRUE)
        return FALSE;

      param_len = len - media_len;
      consumed -= param_len;

      /* Handle Well-Known-Media Long-Integer case */
      if (value_type == WSP_VALUE_TYPE_LONG)
        {
          const unsigned char *pdu_val = data;
          unsigned int var = 0;
          unsigned int i;

          if (value_len > sizeof(unsigned int))
            return FALSE;

          for (i = 0; i < value_len; i++)
            var = (var << 8) | pdu_val[i + 1];

          data = get_text_entry (var, extension_mimetypes);
        }
    }

  if (value_type == WSP_VALUE_TYPE_SHORT)
    {
      const unsigned char *pdu_val = data;
      unsigned int val;

      val = *pdu_val & 0x7f;

      if (val >= LAST_CONTENT_TYPE)
        return FALSE;

      data = content_types[val];
    }

  if (out_value)
    *out_value = data;

  if (out_read)
    *out_read = consumed;

  if (out_param_len)
    *out_param_len = param_len;

  return TRUE;
}

gboolean
wsp_decode_application_id (struct wsp_header_iter *iter,
                           const void            **out_value)
{
  const unsigned char *pdu_val = wsp_header_iter_get_val (iter);
  unsigned int val;
  unsigned int val_len;
  unsigned int i;

  switch (wsp_header_iter_get_val_type (iter))
    {
    case WSP_VALUE_TYPE_TEXT:
      if (out_value)
        *out_value = pdu_val;

      break;

    /*
     * Well-known field values MUST be encoded using the
     * compact binary formats
     */
    case WSP_VALUE_TYPE_SHORT:
      val = *pdu_val & 0x7f;

      if (out_value)
        *out_value = get_text_entry (val, app_id);

      break;

    case WSP_VALUE_TYPE_LONG:
      val_len = wsp_header_iter_get_val_len (iter);

      if (val_len > 2)
        return FALSE;

      for (i = 0, val = 0; i < val_len && i < sizeof(val); i++)
        val = (val << 8) | pdu_val[i];

      if (out_value)
        *out_value = get_text_entry (val, app_id);

      break;
    default:
      g_warning ("Unhandled case");
      return FALSE;
    }

  return TRUE;
}

static inline gboolean
is_content_type_header (const unsigned char *pdu,
                        unsigned char        code_page,
                        unsigned int         flags)
{
  /* Check for MMS Content-Type header */
  if (flags & WSP_HEADER_ITER_FLAG_DETECT_MMS_MULTIPART)
    if (code_page == 1 && *pdu == 0x84)
      return TRUE;

  /* Check for WSP default Content-Type header */
  if (code_page == 1 && *pdu == 0x91)
    return TRUE;

  return FALSE;
}

gboolean
wsp_encode_uintvar (unsigned int   value,
                    unsigned char *dest,
                    unsigned int   dest_size,
                    unsigned int  *written)
{
  unsigned char d[5];
  unsigned int count = 0;

  /* Separate into 7-bit chunks, LS first */
  while (value || !count)
    {
      d[count++] = value & 0x7F;
      value = value >> 7;
    }

  if (count > dest_size)
    return FALSE;

  *written = count;

  /*
   * Output to stream, MS first!
   * 0x80 flag = "continue". LS byte does not have this flag.
   */
  while (--count)
    *dest++ = d[count] | 0x80;

  *dest = d[count];

  return TRUE;
}

gboolean
wsp_encode_value_length (unsigned int   len,
                         unsigned char *dest,
                         unsigned int   dest_size,
                         unsigned int  *written)
{
  if (dest_size < 1)
    return FALSE;

  if (len <= 30)
    {
      *dest = len;
      *written = 1;

      return TRUE;
    }

  /* 31 is escape for variable length int */
  *dest++ = 31;
  dest_size--;

  if (wsp_encode_uintvar (len, dest, dest_size, written) == FALSE)
    return FALSE;

  *written += 1;

  return TRUE;
}

gboolean
wsp_encode_integer (unsigned int   value,
                    unsigned char *dest,
                    unsigned int   dest_size,
                    unsigned int  *written)
{
  unsigned char moi[sizeof(unsigned int)];
  unsigned int count;

  if (dest_size < 1)
    return FALSE;

  if (value < 0x80)
    {
      *dest = value | 0x80;
      *written = 1;

      return TRUE;
    }

  for (count = 0; count < sizeof(unsigned int) && value; count++)
    {
      moi[count] = value & 0xFF;
      value = value >> 8;
    }

  if (count + 1 > dest_size)
    return FALSE;

  *written = count + 1;
  *dest++ = count;

  for (; count > 0; count--)
    *dest++ = moi[count - 1];

  return TRUE;
}

void
wsp_header_iter_init (struct wsp_header_iter *iter,
                      const unsigned char    *pdu,
                      unsigned int            len,
                      unsigned int            flags)
{
  iter->pdu = pdu;
  iter->pos = 0;
  iter->max = len;
  iter->code_page = 1;
  iter->flags = flags;
}

gboolean
wsp_header_iter_next (struct wsp_header_iter *iter)
{
  const unsigned char *pdu = iter->pdu + iter->pos;
  const unsigned char *end = iter->pdu + iter->max;
  enum wsp_header_type header;
  const void *hdr;
  unsigned int consumed;

  if (pdu == end)
    return FALSE;

  /*
   * 8.4.2.6 Header
   * The following rules are used to encode headers.
   * Header = Message-header | Shift-sequence
   * Shift-sequence = (Shift-delimiter Page-identity) |
   *					Short-cut-shift-delimiter
   * Shift-delimiter = <Octet 127>
   * Page-identity = <Any octet 1-255>
   * Short-cut-shift-delimiter = <Any octet 1-31>
   * Message-header = Well-known-header | Application-header
   * Well-known-header = Well-known-field-name Wap-value
   * Application-header = Token-text Application-specific-value
   * Well-known-field-name = Short-integer
   * Application-specific-value = Text-string
   */
  while (*pdu == 127 || (*pdu >= 1 && *pdu <= 31))
    {
      if (iter->flags & WSP_HEADER_ITER_FLAG_REJECT_CP)
        return FALSE;

      if (*pdu == 127)
        {
          pdu++;

          if (pdu == end)
            return FALSE;

          iter->code_page = *pdu;
          pdu++;
        }
      else
        iter->code_page = *pdu++;
    }

  if (pdu == end)
    return FALSE;

  if (*pdu >= 0x80)
    {
      if (is_content_type_header (pdu, iter->code_page, iter->flags))
        return FALSE;

      header = WSP_HEADER_TYPE_WELL_KNOWN;
      hdr = pdu;
      pdu++;
    }
  else {
      if (wsp_decode_token_text (pdu, end - pdu, &consumed) == NULL)
        return FALSE;

      header = WSP_HEADER_TYPE_APPLICATION;
      hdr = pdu;
      pdu += consumed;
    }

  if (pdu == end)
    return FALSE;

  /*
   * Section 8.4.1.2 of WAP-230:
   * If the field name is encoded in text format, textual values MUST
   * be used.
   */
  if ((*pdu < 32 || *pdu > 127) && header == WSP_HEADER_TYPE_APPLICATION)
    return FALSE;

  if (wsp_decode_field (pdu, end - pdu, &iter->value_type,
                        &iter->value, &iter->len, &consumed) == FALSE)
    return FALSE;

  iter->header_type = header;
  iter->header = hdr;

  iter->pos = pdu + consumed - iter->pdu;

  return TRUE;
}

unsigned char
wsp_header_iter_get_code_page (struct wsp_header_iter *iter)
{
  return iter->code_page;
}

gboolean
wsp_header_iter_at_end (struct wsp_header_iter *iter)
{
  if (iter->pos == iter->max)
    return TRUE;

  return FALSE;
}

gboolean
wsp_header_iter_is_multipart (struct wsp_header_iter *iter)
{
  const unsigned char *pdu = iter->pdu + iter->pos;

  return is_content_type_header (pdu, iter->code_page, iter->flags);
}

enum wsp_header_type
wsp_header_iter_get_hdr_type (struct wsp_header_iter *iter)
{
  return iter->header_type;
}

const unsigned char *
wsp_header_iter_get_pdu (struct wsp_header_iter *iter)
{
  return iter->pdu;
}

const void *
wsp_header_iter_get_hdr (struct wsp_header_iter *iter)
{
  return iter->header;
}

enum wsp_value_type
wsp_header_iter_get_val_type (struct wsp_header_iter *iter)
{
  return iter->value_type;
}

const void *
wsp_header_iter_get_val (struct wsp_header_iter *iter)
{
  return iter->value;
}

unsigned int
wsp_header_iter_get_val_len (struct wsp_header_iter *iter)
{
  return iter->len;
}

gboolean
wsp_multipart_iter_init (struct wsp_multipart_iter *mi,
                         struct wsp_header_iter    *hi,
                         const void               **out_content_type,
                         unsigned int              *out_content_type_len)
{
  const unsigned char *pdu = hi->pdu + hi->pos;
  const unsigned char *end = hi->pdu + hi->max;
  unsigned int consumed;
  unsigned int ct_len;

  /* Assume content-type header is well known */
  if (pdu + 1 > end)
    return FALSE;

  pdu++;

  /* Consume the Content-Type value of Content-Type header */
  if (wsp_decode_field (pdu, end - pdu,
                        NULL, NULL, NULL, &consumed) == FALSE)
    return FALSE;

  pdu += consumed;
  ct_len = consumed;

  /*
   * Consume the uinvar specifying the number of parts.  This is set to
   * 0 in later specifications and can be safely ignored
   */
  if (wsp_decode_uintvar (pdu, end - pdu, NULL, &consumed) == FALSE)
    return FALSE;

  memset (mi, 0, sizeof(*mi));
  mi->pdu = hi->pdu + hi->pos;
  mi->max = hi->max - hi->pos;
  mi->pos = pdu + consumed - mi->pdu;

  if (out_content_type)
    *out_content_type = mi->pdu + 1;

  if (out_content_type_len)
    *out_content_type_len = ct_len;

  return TRUE;
}

gboolean
wsp_multipart_iter_next (struct wsp_multipart_iter *mi)
{
  const unsigned char *pdu = mi->pdu + mi->pos;
  const unsigned char *end = mi->pdu + mi->max;
  unsigned int headers_len;
  unsigned int body_len;
  unsigned int consumed;

  if (wsp_decode_uintvar (pdu, end - pdu,
                          &headers_len, &consumed) == FALSE)
    return FALSE;

  pdu += consumed;

  if (wsp_decode_uintvar (pdu, end - pdu, &body_len, &consumed) == FALSE)
    return FALSE;

  pdu += consumed;

  if (pdu + headers_len + body_len > end)
    return FALSE;

  /* Consume the Content-Type value */
  if (wsp_decode_field (pdu, end - pdu,
                        NULL, NULL, NULL, &consumed) == FALSE)
    return FALSE;

  mi->content_type = pdu;
  mi->content_type_len = consumed;
  mi->headers = pdu + consumed;
  mi->headers_len = headers_len - consumed;
  mi->body = pdu + headers_len;
  mi->body_len = body_len;

  mi->pos = pdu - mi->pdu + headers_len + body_len;

  return TRUE;
}

const void *
wsp_multipart_iter_get_content_type (struct wsp_multipart_iter *mi)
{
  return mi->content_type;
}

unsigned int
wsp_multipart_iter_get_content_type_len (
  struct wsp_multipart_iter *mi)
{
  return mi->content_type_len;
}

const void *
wsp_multipart_iter_get_hdr (struct wsp_multipart_iter *mi)
{
  return mi->headers;
}

unsigned int
wsp_multipart_iter_get_hdr_len (struct wsp_multipart_iter *mi)
{
  return mi->headers_len;
}

const void *
wsp_multipart_iter_get_body (struct wsp_multipart_iter *mi)
{
  return mi->body;
}

unsigned int
wsp_multipart_iter_get_body_len (struct wsp_multipart_iter *mi)
{
  return mi->body_len;
}

gboolean
wsp_multipart_iter_close (struct wsp_multipart_iter *mi,
                          struct wsp_header_iter    *hi)
{
  if (mi->pos != mi->max)
    return FALSE;

  hi->pos += mi->pos;

  return TRUE;
}

void
wsp_parameter_iter_init (struct wsp_parameter_iter *pi,
                         const unsigned char       *pdu,
                         unsigned int               len)
{
  pi->pdu = pdu;
  pi->max = len;
  pi->pos = 0;
}

gboolean
wsp_parameter_iter_next (struct wsp_parameter_iter *pi,
                         struct wsp_parameter      *out)
{
  const unsigned char *pdu = pi->pdu + pi->pos;
  const unsigned char *end = pi->pdu + pi->max;
  unsigned int token;
  unsigned int consumed;
  const char *untyped;
  const char *value;

  /* Well known parameter token */
  if (wsp_decode_integer (pdu, end - pdu, &token, &consumed) == TRUE)
    {
      pdu += consumed;

      switch (token)
        {
        case WSP_PARAMETER_TYPE_LEVEL:
        case WSP_PARAMETER_TYPE_DIFFERENCES:
          if (*pdu & 0x80)
            {
              unsigned int i = *pdu & 0x7f;

              pdu += 1;
              pi->pos = pdu - pi->pdu;

              if (out)
                {
                  out->type = token;
                  out->value = WSP_PARAMETER_VALUE_INT;
                  out->integer = i;
                }

              return TRUE;
            }

        /* Continue to the string case */

        /* fall through */
        case WSP_PARAMETER_TYPE_NAME_DEFUNCT:
        case WSP_PARAMETER_TYPE_FILENAME_DEFUNCT:
        case WSP_PARAMETER_TYPE_START_DEFUNCT:
        case WSP_PARAMETER_TYPE_START_INFO_DEFUNCT:
        case WSP_PARAMETER_TYPE_COMMENT_DEFUNCT:
        case WSP_PARAMETER_TYPE_DOMAIN_DEFUNCT:
        case WSP_PARAMETER_TYPE_PATH_DEFUNCT:
        case WSP_PARAMETER_TYPE_NAME:
        case WSP_PARAMETER_TYPE_FILENAME:
        case WSP_PARAMETER_TYPE_START:
        case WSP_PARAMETER_TYPE_START_INFO:
        case WSP_PARAMETER_TYPE_COMMENT:
        case WSP_PARAMETER_TYPE_DOMAIN:
        case WSP_PARAMETER_TYPE_PATH:
        case WSP_PARAMETER_TYPE_MAC:
        {
          const char *text = wsp_decode_text (pdu, end - pdu,
                                              &consumed);

          if (text == NULL)
            return FALSE;

          pdu += consumed;
          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_TEXT;
              out->text = text;
            }

          return TRUE;
        }

        case WSP_PARAMETER_TYPE_TYPE:
        case WSP_PARAMETER_TYPE_SIZE:
        case WSP_PARAMETER_TYPE_MAX_AGE:
        {
          unsigned int i;

          if (wsp_decode_integer (pdu, end - pdu,
                                  &i, &consumed) == FALSE)
            return FALSE;

          pdu += consumed;
          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_INT;
              out->integer = i;
            }

          return TRUE;
        }

        case WSP_PARAMETER_TYPE_PADDING:
        case WSP_PARAMETER_TYPE_SEC:
          if ((*pdu & 0x80) == 0)
            return FALSE;

          pdu += 1;
          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_INT;
              out->integer = *pdu & 0x7f;
            }

          return TRUE;

        case WSP_PARAMETER_TYPE_CREATION_DATE:
        case WSP_PARAMETER_TYPE_MODIFICATION_DATE:
        case WSP_PARAMETER_TYPE_READ_DATE:
        {
          unsigned int i;

          if (wsp_decode_integer (pdu, end - pdu,
                                  &i, &consumed) == FALSE)
            return FALSE;

          pdu += consumed;
          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_DATE;
              out->integer = i;
            }

          return TRUE;
        }

        case WSP_PARAMETER_TYPE_SECURE:
          if (*pdu != 0)
            return FALSE;

          pdu += 1;
          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_TEXT;
              out->text = (const char *) pdu - 1;
            }

          return TRUE;

        case WSP_PARAMETER_TYPE_CHARSET:
        {
          unsigned int i;
          const char *charset;

          if (wsp_decode_integer (pdu, end - pdu,
                                  &i, &consumed) == FALSE)
            return FALSE;

          charset = get_text_entry (i, charset_assignments);
          if (charset == NULL)
            return FALSE;

          pdu += consumed;
          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_TEXT;
              out->text = charset;
            }

          return TRUE;
        }

        case WSP_PARAMETER_TYPE_CONTENT_TYPE:
        {
          const char *ct;

          if (*pdu & 0x80)
            {
              unsigned int i = *pdu & 0x7f;

              if (i >= LAST_CONTENT_TYPE)
                return FALSE;

              ct = content_types[i];
              pdu += 1;
            }
          else if ((ct = wsp_decode_text (pdu, end - pdu,
                                          &consumed)))
            pdu += consumed;
          else
            return FALSE;

          pi->pos = pdu - pi->pdu;

          if (out)
            {
              out->type = token;
              out->value = WSP_PARAMETER_VALUE_TEXT;
              out->text = ct;
            }

          return TRUE;
        }

        /* TODO */
        case WSP_PARAMETER_TYPE_Q:
        default:
          return FALSE;
        }
    }

  untyped = wsp_decode_text (pdu, end - pdu, &consumed);
  if (untyped == NULL)
    return FALSE;

  pdu += consumed;

  if (wsp_decode_integer (pdu, end - pdu, &token, &consumed) == TRUE)
    {
      pdu += consumed;
      pi->pos = pdu - pi->pdu;

      out->type = WSP_PARAMETER_TYPE_UNTYPED;
      out->value = WSP_PARAMETER_VALUE_INT;
      out->integer = token;
      out->untyped = untyped;

      return TRUE;
    }

  value = wsp_decode_text (pdu, end - pdu, &consumed);
  if (value == NULL)
    return FALSE;

  pdu += consumed;
  pi->pos = pdu - pi->pdu;

  out->type = WSP_PARAMETER_TYPE_UNTYPED;
  out->value = WSP_PARAMETER_VALUE_TEXT;
  out->text = value;
  out->untyped = untyped;

  return TRUE;
}

static const char *
decode_token (char         *buf,
              gboolean      accept_quotes,
              unsigned int *out_consumed,
              char         *out_terminator)
{
  unsigned int pos = 0;
  unsigned int start;
  unsigned int end;
  char *endp;
  char terminator = '\0';

  /* Skip leading space */
  while (buf[pos] == ' ' || buf[pos] == '\t')
    pos += 1;

  if (buf[pos] == '\0')
    return NULL;

  start = pos;

  if (buf[pos] == '"')
    {
      if (accept_quotes == FALSE)
        return NULL;

      pos += 1;
      start = pos;

      endp = strchr (buf + pos, '"');
      if (endp == NULL)
        return NULL;

      pos = endp - buf;
      end = pos;
      pos += 1;
    }
  else {
      endp = strpbrk (buf + pos, sep_chars);

      if (endp == NULL)
        pos = strlen (buf);
      else
        pos = endp - buf;

      end = pos;
    }

  while (buf[pos] == ' ' || buf[pos] == '\t')
    pos += 1;

  if (buf[pos] != '\0')
    {
      terminator = buf[pos];
      pos += 1;
    }

  buf[end] = '\0';

  if (strpbrk (buf + start, ctl_chars) != NULL)
    return NULL;

  *out_consumed = pos;
  *out_terminator = terminator;

  return buf + start;
}

gboolean
wsp_text_header_iter_init (struct wsp_text_header_iter *iter,
                           const char                  *hdr)
{
  unsigned int len = strlen (hdr);
  char terminator;
  unsigned int consumed;
  const char *key;
  const char *value;

  if (len > MAX_TEXT_HEADER_SIZE)
    return FALSE;

  memcpy (iter->hdr, hdr, len);
  iter->hdr[len] = '\0';
  iter->pos = 0;
  iter->key = NULL;
  iter->value = NULL;

  key = decode_token (iter->hdr, FALSE, &consumed, &terminator);
  if (key == NULL)
    return FALSE;

  if (terminator != ':')
    return FALSE;

  len = consumed;

  value = decode_token (iter->hdr + len, TRUE, &consumed, &terminator);
  if (value == NULL)
    return FALSE;

  if (terminator != '\0' && terminator != ';')
    return FALSE;

  len += consumed;

  iter->key = key;
  iter->value = value;
  iter->pos = len;

  return TRUE;
}

gboolean
wsp_text_header_iter_param_next (struct wsp_text_header_iter *iter)
{
  unsigned int pos = iter->pos;
  char terminator;
  unsigned int consumed;
  const char *key;
  const char *value;

  key = decode_token (iter->hdr + pos, FALSE, &consumed, &terminator);
  if (key == NULL)
    return FALSE;

  /* Empty value */
  if (terminator == ';' || terminator == '\0')
    {
      iter->key = key;
      iter->value = NULL;
      iter->pos += consumed;

      return TRUE;
    }

  if (terminator != '=')
    return FALSE;

  pos += consumed;

  value = decode_token (iter->hdr + pos, TRUE, &consumed, &terminator);
  if (value == NULL)
    return FALSE;

  if (terminator != '\0' && terminator != ';')
    return FALSE;

  pos += consumed;

  iter->key = key;
  iter->value = value;
  iter->pos = pos;

  return TRUE;
}

const char *
wsp_text_header_iter_get_key (struct wsp_text_header_iter *iter)
{
  return iter->key;
}

const char *
wsp_text_header_iter_get_value (struct wsp_text_header_iter *iter)
{
  return iter->value;
}
