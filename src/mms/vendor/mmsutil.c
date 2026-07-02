/*
 * ---------------------------------------------------------------------
 * Vendored from mmsd-tng (https://gitlab.com/kop316/mmsd)
 * Upstream file:   src/mmsutil.c
 * Upstream commit: 341117141f8d30949fb1294cc71ee44af9b4c90f
 * Vendored on:     2026-07-02
 *
 * Local modifications (chan_modemmanager, src/mms/vendor/mmsutil.c):
 *   - Replaced `#include "mms.h"` with `#include "vendor_shim.h"`.
 *     Upstream's mms.h is a daemon-composition header that pulls in
 *     plugin.h, service.h, store.h, itu-e212-iso.h and log.h. This file
 *     (verified by grep across the whole file) only ever uses one
 *     symbol from that chain: the DBG() logging macro from log.h.
 *     vendor_shim.h supplies an equivalent local DBG() macro (documented
 *     there) plus <glib.h>, without dragging in the rest of the mmsd-tng
 *     daemon's headers/build system, which this project has no
 *     equivalent of and does not need for a pure codec.
 *   - No other changes. In particular, the M-Send.Req/M-NotifyResp.Ind
 *     *encode* path (mms_message_encode() and friends, further down in
 *     this file) was left in near-verbatim, unmodified, and untrimmed:
 *     it only touches libc (write()/lseek() style POSIX I/O via a
 *     small internal `struct file_buffer`) and GLib, both of which are
 *     already vendored/linked here, so nothing needed to be deleted.
 *     It is unused by mms_codec.c (see src/mms/mms_codec.c) but is kept
 *     for parity with upstream and potential future use (e.g. MMS
 *     sending) in a later step.
 * ---------------------------------------------------------------------
 */

/*
 *
 *  Multimedia Messaging Service Daemon - The Next Generation
 *
 *  Copyright (C) 2010-2011, Intel Corporation
 *                2021, Chris Talbot <chris@talbothome.com>
 *                2020, Anteater <nt8r@protonmail.com>
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

#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#include "wsputil.h"
#include "mmsutil.h"
#include "vendor_shim.h"

#define MAX_ENC_VALUE_BYTES 6

#ifdef TEMP_FAILURE_RETRY
#define TFR TEMP_FAILURE_RETRY
#else
#define TFR
#endif

#define uninitialized_var(x) x = x

enum header_flag {
  HEADER_FLAG_MANDATORY =                 1,
  HEADER_FLAG_ALLOW_MULTI =               2,
  HEADER_FLAG_PRESET_POS =                4,
  HEADER_FLAG_MARKED =                    8,
};

/*
 * See http://www.openmobilealliance.org/release/MMS/V1_3-20110913-A/OMA-TS-MMS_ENC-V1_3-20110913-A.pdf
 * Table 25 for a list of these headers.
 */
//	Internal usage by mmsd-tng			Hex and Name on Table 25
enum mms_header {
  MMS_HEADER_BCC =                                0x01,       // Bcc
  MMS_HEADER_CC =                                 0x02,       // Cc
  MMS_HEADER_CONTENT_LOCATION =                   0x03,       // X-Mms-Content-Location
  MMS_HEADER_CONTENT_TYPE =                       0x04,       // Content-Type
  MMS_HEADER_DATE =                               0x05,       // Date
  MMS_HEADER_DELIVERY_REPORT =                    0x06,       // X-Mms-Delivery-Report
  MMS_HEADER_DELIVERY_TIME =                      0x07,       // X-Mms-Delivery-Time
  MMS_HEADER_EXPIRY =                             0x08,       // X-Mms-Expiry
  MMS_HEADER_FROM =                               0x09,       // From
  MMS_HEADER_MESSAGE_CLASS =                      0x0a,       // X-Mms-Message-Class
  MMS_HEADER_MESSAGE_ID =                         0x0b,       // Message-ID
  MMS_HEADER_MESSAGE_TYPE =                       0x0c,       // X-Mms-Message-Type
  MMS_HEADER_MMS_VERSION =                        0x0d,       // X-Mms-MMS-Version
  MMS_HEADER_MESSAGE_SIZE =                       0x0e,       // X-Mms-Message-Size
  MMS_HEADER_PRIORITY =                           0x0f,       // X-Mms-Priority
  MMS_HEADER_READ_REPLY =                         0x10,       // X-Mms-Read-Report
  MMS_HEADER_REPORT_ALLOWED =                     0x11,       // X-Mms-Report-Allowed
  MMS_HEADER_RESPONSE_STATUS =                    0x12,       // X-Mms-Response-Status
  MMS_HEADER_RESPONSE_TEXT =                      0x13,       // X-Mms-Response-Text
  MMS_HEADER_SENDER_VISIBILITY =                  0x14,       // X-Mms-Sender-Visibility
  MMS_HEADER_STATUS =                             0x15,       // X-Mms-Status
  MMS_HEADER_SUBJECT =                            0x16,       // Subject
  MMS_HEADER_TO =                                 0x17,       // To
  MMS_HEADER_TRANSACTION_ID =                     0x18,       // X-Mms-Transaction-Id
  MMS_HEADER_RETRIEVE_STATUS =                    0x19,       // X-Mms-Retrieve-Status
  MMS_HEADER_RETRIEVE_TEXT =                      0x1a,       // X-Mms-Retrieve-Text
  MMS_HEADER_READ_STATUS =                        0x1b,       // X-Mms-Read-Status
  MMS_HEADER_REPLY_CHARGING =                     0x1c,       // X-Mms-Reply-Charging
  MMS_HEADER_REPLY_CHARGING_DEADLINE =            0x1d,       // X-Mms-Reply-Charging-Deadline
  MMS_HEADER_REPLY_CHARGING_ID =                  0x1e,       // X-Mms-Reply-Charging-ID
  MMS_HEADER_REPLY_CHARGING_SIZE =                0x1f,       // X-Mms-Reply-Charging-Size
  MMS_HEADER_PREVIOUSLY_SENT_BY =                 0x20,       // X-Mms-Previously-Sent-By
  MMS_HEADER_PREVIOUSLY_SENT_DATE =               0x21,       // X-Mms-Previously-Sent-Date
  MMS_HEADER_STORE =                              0x22,       // X-Mms-Store
  MMS_HEADER_MM_STATE =                           0x23,       // X-Mms-MM-State
  MMS_HEADER_MM_FLAGS =                           0x24,       // X-Mms-MM-Flags
  MMS_HEADER_STORE_STATUS =                       0x25,       // X-Mms-Store-Status
  MMS_HEADER_STORE_STATUS_TEXT =                  0x26,       // X-Mms-Store-Status-Text
  MMS_HEADER_STORED =                             0x27,       // X-Mms-Stored
  MMS_HEADER_ATTRIBUTES =                         0x28,       // X-Mms-Attributes
  MMS_HEADER_TOTALS =                             0x29,       // X-Mms-Totals
  MMS_HEADER_MBOX_TOTALS =                        0x2a,       // X-Mms-Mbox-Totals
  MMS_HEADER_QUOTAS =                             0x2b,       // X-Mms-Quotas
  MMS_HEADER_MBOX_QUOTAS =                        0x2c,       // X-Mms-Mbox-Quotas
  MMS_HEADER_MESSAGE_COUNT =                      0x2d,       // X-Mms-Message-Count
  MMS_HEADER_CONTENT =                            0x2e,       // Content
  MMS_HEADER_START =                              0x2f,       // X-Mms-Start
  MMS_HEADER_ADDITIONAL_HEADERS =                 0x30,       // Additional-headers
  MMS_HEADER_DISTRIBUTION_INDICATOR =             0x31,       // X-Mms-Distribution-Indicator
  MMS_HEADER_ELEMENT_DESCRIPTOR =                 0x32,       // X-Mms-Element-Descriptor
  MMS_HEADER_LIMIT =                              0x33,       // X-Mms-Limit
  MMS_HEADER_RECOMMENDED_RETRIEVAL_MODE =         0x34,       // X-Mms-Recommended-Retrieval-Mode
  MMS_HEADER_RECOMMENDED_RETRIEVAL_MODE_TEXT =    0x35,       // X-Mms-Recommended-Retrieval-Mode-Text
  MMS_HEADER_STATUS_TEST =                        0x36,       // X-Mms-Status-Text
  MMS_HEADER_APPLICATION_ID =                     0x37,       // X-Mms-Applic-ID
  MMS_HEADER_REPLY_APPLICATION_ID =               0x38,       // X-Mms-Reply-Applic-ID
  MMS_HEADER_AUX_APPLICATION_INFO =               0x39,       // X-Mms-Aux-Applic-Info
  MMS_HEADER_CONTENT_CLASS =                      0x3a,       // X-Mms-Content-Class
  MMS_HEADER_DRM_CONTACT =                        0x3b,       // X-Mms-DRM-Content
  MMS_HEADER_ADAPTATION_ALLOWED =                 0x3c,       // X-Mms-Adaptation-Allowed
  MMS_HEADER_REPLACE_ID =                         0x3d,       // X-Mms-Replace-ID
  MMS_HEADER_CANCEL_ID =                          0x3e,       // X-Mms-Cancel-ID
  MMS_HEADER_CANCEL_STATUS =                      0x3f,       // X-Mms-Cancel-Status
  __MMS_HEADER_MAX =                              0x40,       // Used to indicate largest header in mmsd-tng
  MMS_HEADER_INVALID =                            0x80,       // Used to indicate the end of the headers in mmsd-tng
};

enum mms_part_header {
  MMS_PART_HEADER_CONTENT_LOCATION =      0x0e,
  MMS_PART_HEADER_CONTENT_ID =            0x40,
};

/*
 * IANA Character Set Assignments (examples) used by WAPWSP
 *
 * Reference: WAP-230-WSP Appendix Table 42 Character Set Assignment Examples
 * Reference: IANA http://www.iana.org/assignments/character-sets
 */
static const struct
{
  unsigned int mib_enum;
  const char *charset;
} charset_assignments[] = {
  { 0x03, "us-ascii"      },
  { 0x6A, "utf-8"         },
  { 0x00, NULL            }
};

#define FB_SIZE 256

struct file_buffer
{
  unsigned char buf[FB_SIZE];
  unsigned int size;
  unsigned int fsize;
  int fd;
};

typedef gboolean (*header_handler)(struct wsp_header_iter *,
                                   void *);
typedef gboolean (*header_encoder)(struct file_buffer *,
                                   enum mms_header,
                                   void *);

char *
mms_content_type_get_param_value (const char *content_type,
                                  const char *param_name)
{
  struct wsp_text_header_iter iter;

  if (wsp_text_header_iter_init (&iter, content_type) == FALSE)
    return NULL;

  while (wsp_text_header_iter_param_next (&iter) == TRUE)
    {
      const char *key = wsp_text_header_iter_get_key (&iter);

      if (g_str_equal (key, param_name) == TRUE)
        return g_strdup (wsp_text_header_iter_get_value (&iter));
    }

  return NULL;
}

static const char *
charset_index2string (unsigned int index)
{
  unsigned int i = 0;

  for (i = 0; charset_assignments[i].charset; i++)
    if (charset_assignments[i].mib_enum == index)
      return charset_assignments[i].charset;

  return NULL;
}

static gboolean
extract_short (struct wsp_header_iter *iter,
               void                   *user)
{
  unsigned char *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);
  *out = p[0];

  return TRUE;
}

static const char *
decode_text (struct wsp_header_iter *iter)
{
  const unsigned char *p;
  unsigned int l = 32;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_TEXT)
    {
      p = wsp_header_iter_get_val (iter);
      DBG ("could not decode text of (dummy) length %u: %*s", l - 1, l - 1, p + 1);
      return NULL;
    }

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);
  DBG ("claimed len: %u", l);
  DBG ("val: %*s", l - 1, p);

  return wsp_decode_text (p, l, NULL);
}

static gboolean
extract_text (struct wsp_header_iter *iter,
              void                   *user)
{
  char **out = user;
  const char *text;

  text = decode_text (iter);
  if (text == NULL)
    return FALSE;

  *out = g_strdup (text);

  return TRUE;
}

static char *
remove_address_type_suffix (const char *addr,
                            size_t      len)
{
  return g_strdup (addr);
/*	#define MMS_ADDR_SUFFIX_PUBLIC_LAND_MOBILE_NUMBER "/TYPE=PLMN"
 *      if(g_str_has_suffix(addr, MMS_ADDR_SUFFIX_PUBLIC_LAND_MOBILE_NUMBER)) {
 *              return g_strndup(addr, len - strlen(MMS_ADDR_SUFFIX_PUBLIC_LAND_MOBILE_NUMBER));
 *      } else {
 *              return g_strdup(addr);
 *      }*/
}

static char *
decode_encoded_string_with_mib_enum (const unsigned char *p,
                                     unsigned int         l)
{
  unsigned int mib_enum;
  unsigned int consumed;
  const char *text;
  const char *from_codeset;
  const char *to_codeset = "UTF-8";
  gsize bytes_read;
  gsize bytes_written;

  if (wsp_decode_integer (p, l, &mib_enum, &consumed) == FALSE)
    return NULL;

  if (mib_enum == 106)
    {
      /* header is UTF-8 already */
      text = wsp_decode_text (p + consumed, l - consumed, NULL);

      return g_strdup (text);
    }

  /* convert to UTF-8 */
  from_codeset = charset_index2string (mib_enum);
  if (from_codeset == NULL)
    return NULL;

  return g_convert ((const char *) p + consumed, l - consumed,
                    to_codeset, from_codeset,
                    &bytes_read, &bytes_written, NULL);
}

static gboolean
extract_text_array_element (struct wsp_header_iter *iter,
                            void                   *user)
{
  char **out = user;
  const char *wsp_decoded_text;
  char *tmp;
  const unsigned char *p;
  unsigned int l;
  g_autofree char *element = NULL;

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  switch (wsp_header_iter_get_val_type (iter))
    {
    case WSP_VALUE_TYPE_TEXT:
      /* Text-string */
      wsp_decoded_text = wsp_decode_text (p, l, NULL);
      element = g_strdup (wsp_decoded_text);
      break;
    case WSP_VALUE_TYPE_LONG:
      /* (Value-len) Char-set Text-string */
      element = decode_encoded_string_with_mib_enum (p, l);
      break;
    case WSP_VALUE_TYPE_SHORT:
      element = NULL;
      break;
    default:
      g_warning ("Unhandled case");
      element = NULL;
      break;
    }

  if (element == NULL)
    {
      DBG ("failed, type=%d", wsp_header_iter_get_val_type (iter));
      return FALSE;
    }

  if (*out == NULL)
    {
      *out = g_strdup (element);
      return TRUE;
    }

  tmp = g_strjoin (",", *out, element, NULL);
  if (tmp == NULL)
    {
      DBG ("join failed");
      return FALSE;
    }

  g_free (*out);

  *out = tmp;

  return TRUE;
}

static gboolean
extract_encoded_text (struct wsp_header_iter *iter,
                      void                   *user)
{
  char **out = user;
  const unsigned char *p;
  unsigned int l;
  const char *text;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
  char *uninitialized_var (dec_text);
#pragma GCC diagnostic pop

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  if (l == 0)
    {
      DBG ("Length is 0! Returning empty string");
      dec_text = g_strdup ("");
      *out = dec_text;
      return TRUE;
    }

  switch (wsp_header_iter_get_val_type (iter))
    {
    case WSP_VALUE_TYPE_TEXT:
      /* Text-string */
      text = wsp_decode_text (p, l, NULL);
      dec_text = g_strdup (text);
      break;
    case WSP_VALUE_TYPE_LONG:
      /* (Value-len) Char-set Text-string */
      dec_text = decode_encoded_string_with_mib_enum (p, l);
      break;
    case WSP_VALUE_TYPE_SHORT:
      dec_text = NULL;
      break;
    default:
      g_warning ("Unhandled case");
      dec_text = NULL;
      break;
    }

  if (dec_text == NULL)
    return FALSE;

  *out = dec_text;

  return TRUE;
}

static gboolean
extract_date (struct wsp_header_iter *iter,
              void                   *user)
{
  time_t *out = user;
  const unsigned char *p;
  unsigned int l;
  unsigned int i;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_LONG)
    return FALSE;

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  if (l > 4)
    return FALSE;

  for (i = 0, *out = 0; i < l; i++)
    *out = *out << 8 | p[i];

  /* It is possible to overflow time_t on 32 bit systems */
  *out = *out & 0x7fffffff;

  return TRUE;
}

static gboolean
extract_absolute_relative_date (struct wsp_header_iter *iter,
                                void                   *user)
{
  time_t *out = user;
  const unsigned char *p;
  unsigned int l;
  unsigned int i;
  unsigned int seconds;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_LONG)
    return FALSE;

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  if (l < 2 || l > 5)
    return FALSE;

  if (p[0] != 128 && p[0] != 129)
    return FALSE;

  for (i = 2, seconds = 0; i < l; i++)
    seconds = seconds << 8 | p[i];

  if (p[0] == 129)
    {
      *out = time (NULL);
      *out += seconds;
    }
  else
    *out = seconds;

  /* It is possible to overflow time_t on 32 bit systems */
  *out = *out & 0x7fffffff;

  return TRUE;
}

static gboolean
extract_boolean (struct wsp_header_iter *iter,
                 void                   *user)
{
  gboolean *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  if (p[0] != 128 && p[0] != 129)
    return FALSE;

  *out = p[0] == 128;

  return TRUE;
}

static gboolean
extract_from (struct wsp_header_iter *iter,
              void                   *user)
{
  char **out = user;
  const unsigned char *p;
  unsigned int l;
  const char *text;
  unsigned int val_len;
  unsigned int str_len;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_LONG)
    {
      DBG ("val_type not LONG");
      return FALSE;
    }

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  /* From-value = Value-length (Address-present-token=128 Encoded-string-value | Insert-address-token=129) */
  /* Encoded-string-value = Text-string | Value-length Char-set Text-string */
  /* Value-length = Short-length | (Length-quote Length) */
  /* Short-length = val 0-30 */
  /* Length-quote = val 31 */
  /* Length = Uintvar-integer */

  if (p[0] != 128 && p[0] != 129)
    {
      DBG ("not 128 or 129");
      return FALSE;
    }

  if (p[0] == 129)
    {
      *out = NULL;
      return TRUE;
    }
  p += 1; l -= 1;       /* token has been handled */

  val_len = l;
  if (p[0] < 31)         /*short-length */
    {
      val_len = p[0];
      p += 2;
      val_len -= 1;           /* count encoding against val_len */
    }
  else if (p[0] == 31)         /* length quote then long length */
    {
      unsigned int consumed = 0;
      gboolean ok = wsp_decode_uintvar (p, l, &val_len, &consumed);
      if (!ok)
        return FALSE;
      p += consumed;
      val_len -= 1;           /* count encoding against val_len */
    }
  str_len = val_len - 1;       /* NUL at the end is not counted by strlen() */

  //DBG("trying to decode text of length %u: %*s", str_len, str_len, p);
  text = wsp_decode_text (p, val_len, NULL);
  //DBG("text=\"%s\"", text);

  if (text == NULL)
    {
      DBG ("could not decode text of length %u: %*s", str_len, str_len, p);
      return FALSE;
    }

  DBG ("Successfully decoded text!");
  *out = remove_address_type_suffix (text, str_len);

  return TRUE;
}

static gboolean
extract_message_class (struct wsp_header_iter *iter,
                       void                   *user)
{
  char **out = user;
  const unsigned char *p;
  unsigned int l;
  const char *text;

  if (wsp_header_iter_get_val_type (iter) == WSP_VALUE_TYPE_LONG)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  if (wsp_header_iter_get_val_type (iter) == WSP_VALUE_TYPE_SHORT)
    switch (p[0])
      {
      case 128:
        *out = g_strdup ("Personal");
        return TRUE;
      case 129:
        *out = g_strdup ("Advertisement");
        return TRUE;
      case 130:
        *out = g_strdup ("Informational");
        return TRUE;
      case 131:
        *out = g_strdup ("Auto");
        return TRUE;
      default:
        return FALSE;
      }

  l = wsp_header_iter_get_val_len (iter);

  text = wsp_decode_token_text (p, l, NULL);
  if (text == NULL)
    return FALSE;

  *out = g_strdup (text);

  return TRUE;
}

static gboolean
extract_sender_visibility (struct wsp_header_iter *iter,
                           void                   *user)
{
  enum mms_message_sender_visibility *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  if (p[0] != 128 && p[0] != 129)
    return FALSE;

  *out = p[0];

  return TRUE;
}

static gboolean
extract_priority (struct wsp_header_iter *iter,
                  void                   *user)
{
  char **out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  switch (p[0])
    {
    case 128:
      *out = g_strdup ("Low");
      return TRUE;
    case 129:
      *out = g_strdup ("Normal");
      return TRUE;
    case 130:
      *out = g_strdup ("High");
      return TRUE;
    default:
      return FALSE;
    }

  return TRUE;
}

static gboolean
extract_read_status (struct wsp_header_iter *iter,
                     void                   *user)
{
  enum mms_message_read_status *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  if (p[0] == MMS_MESSAGE_READ_STATUS_READ ||
      p[0] == MMS_MESSAGE_READ_STATUS_DELETED_UNREAD)
    {
      *out = p[0];
      return TRUE;
    }

  return FALSE;
}

static gboolean
extract_retr_status (struct wsp_header_iter *iter,
                     void                   *user)
{
  enum mms_message_retr_status *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  switch (p[0])
    {
    case MMS_MESSAGE_RETR_STATUS_OK:
    case MMS_MESSAGE_RETR_STATUS_ERR_TRANS_FAILURE:
    case MMS_MESSAGE_RETR_STATUS_ERR_TRANS_MESSAGE_NOT_FOUND:
    case MMS_MESSAGE_RETR_STATUS_ERR_PERM_FAILURE:
    case MMS_MESSAGE_RETR_STATUS_ERR_PERM_SERVICE_DENIED:
    case MMS_MESSAGE_RETR_STATUS_ERR_PERM_MESSAGE_NOT_FOUND:
    case MMS_MESSAGE_RETR_STATUS_ERR_PERM_CONTENT_UNSUPPORTED:
      *out = p[0];
      return TRUE;
    default:
      g_warning ("Unhandled case");
      return FALSE;
    }

  return FALSE;
}

static gboolean
extract_rsp_status (struct wsp_header_iter *iter,
                    void                   *user)
{
  unsigned char *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  switch (p[0])
    {
    case MMS_MESSAGE_RSP_STATUS_OK:
    case MMS_MESSAGE_RSP_STATUS_ERR_UNSUPPORTED_MESSAGE:
    case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_FAILURE:
    case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_NETWORK_PROBLEM:
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_FAILURE:
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SERVICE_DENIED:
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_MESSAGE_FORMAT_CORRUPT:
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SENDING_ADDRESS_UNRESOLVED:
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_CONTENT_NOT_ACCEPTED:
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_LACK_OF_PREPAID:
      *out = p[0];
      return TRUE;
    default:
      g_warning ("Unhandled case");
      return FALSE;
    }

  return FALSE;
}

static gboolean
extract_status (struct wsp_header_iter *iter,
                void                   *user)
{
  enum mms_message_delivery_status *out = user;
  const unsigned char *p;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_SHORT)
    return FALSE;

  p = wsp_header_iter_get_val (iter);

  switch (p[0])
    {
    case MMS_MESSAGE_DELIVERY_STATUS_EXPIRED:
    case MMS_MESSAGE_DELIVERY_STATUS_RETRIEVED:
    case MMS_MESSAGE_DELIVERY_STATUS_REJECTED:
    case MMS_MESSAGE_DELIVERY_STATUS_DEFERRED:
    case MMS_MESSAGE_DELIVERY_STATUS_UNRECOGNISED:
    case MMS_MESSAGE_DELIVERY_STATUS_INDETERMINATE:
    case MMS_MESSAGE_DELIVERY_STATUS_FORWARDED:
    case MMS_MESSAGE_DELIVERY_STATUS_UNREACHABLE:
      *out = p[0];
      return TRUE;
    default:
      g_warning ("Unhandled case");
      return FALSE;
    }

  return FALSE;
}

static gboolean
extract_unsigned (struct wsp_header_iter *iter,
                  void                   *user)
{
  unsigned long *out = user;
  const unsigned char *p;
  unsigned int l;
  unsigned int i;

  if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_LONG)
    return FALSE;

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  if (l > sizeof(unsigned long))
    return FALSE;

  for (i = 0, *out = 0; i < l; i++)
    *out = *out << 8 | p[i];

  return TRUE;
}

static header_handler
handler_for_type (enum mms_header header)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
  //Refer to enum mms_header if you need to add headers
  switch (header)
    {
    case MMS_HEADER_BCC:
      return extract_encoded_text;
    case MMS_HEADER_CC:
      return extract_encoded_text;
    case MMS_HEADER_CONTENT_LOCATION:
      return extract_text;
    case MMS_HEADER_CONTENT_TYPE:
      return extract_text;           /* extract_encoded_text? */
    case MMS_HEADER_DATE:
      return extract_date;
    case MMS_HEADER_DELIVERY_REPORT:
      return extract_boolean;
    case MMS_HEADER_DELIVERY_TIME:
      return extract_absolute_relative_date;
    case MMS_HEADER_EXPIRY:
      return extract_absolute_relative_date;
    case MMS_HEADER_FROM:
      return extract_from;
    case MMS_HEADER_MESSAGE_CLASS:
      return extract_message_class;
    case MMS_HEADER_MESSAGE_ID:
      return extract_text;
    case MMS_HEADER_MESSAGE_TYPE:
      return extract_short;
    case MMS_HEADER_MMS_VERSION:
      return extract_short;
    case MMS_HEADER_MESSAGE_SIZE:
      return extract_unsigned;
    case MMS_HEADER_PRIORITY:
      return extract_priority;
    case MMS_HEADER_READ_REPLY:
      return extract_boolean;
    case MMS_HEADER_REPORT_ALLOWED:
      return extract_boolean;
    case MMS_HEADER_RESPONSE_STATUS:
      return extract_rsp_status;
    case MMS_HEADER_RESPONSE_TEXT:
      return extract_encoded_text;
    case MMS_HEADER_RETRIEVE_STATUS:
      return extract_retr_status;
    case MMS_HEADER_RETRIEVE_TEXT:
      return extract_encoded_text;
    case MMS_HEADER_READ_STATUS:
      return extract_read_status;
    case MMS_HEADER_SENDER_VISIBILITY:
      return extract_sender_visibility;
    case MMS_HEADER_STATUS:
      return extract_status;
    case MMS_HEADER_SUBJECT:
      return extract_encoded_text;
    case MMS_HEADER_TO:
      return extract_text_array_element;
    case MMS_HEADER_TRANSACTION_ID:
      return extract_text;
    case MMS_HEADER_INVALID:
    case __MMS_HEADER_MAX:
    default:
      return NULL;
    }
#pragma GCC diagnostic pop
}

struct header_handler_entry
{
  int flags;
  void *data;
  int pos;
};

static gboolean
mms_parse_headers (struct wsp_header_iter *iter,
                   enum mms_header         orig_header,
                   ...)
{
  struct header_handler_entry entries[__MMS_HEADER_MAX + 1];
  va_list args;
  const unsigned char *p;
  unsigned int i;
  enum mms_header header;

  memset (&entries, 0, sizeof(entries));

  va_start (args, orig_header);
  header = orig_header;

  while (header != MMS_HEADER_INVALID)
    {
      entries[header].flags = va_arg (args, int);
      entries[header].data = va_arg (args, void *);

      header = va_arg (args, enum mms_header);
    }

  va_end (args);

  for (i = 1; wsp_header_iter_next (iter); i++)
    {
      unsigned char h;
      header_handler handler;

      /* Skip application headers */
      if (wsp_header_iter_get_hdr_type (iter) !=
          WSP_HEADER_TYPE_WELL_KNOWN)
        continue;

      p = wsp_header_iter_get_hdr (iter);
      h = p[0] & 0x7f;

      handler = handler_for_type (h);
      if (handler == NULL)
        {
          if (h == MMS_HEADER_INVALID)
            {
              g_critical ("Got MMS_HEADER_INVALID: 0x%02X. Returning False", h);
              return FALSE;
            }
          else if (h == __MMS_HEADER_MAX)
            {
              g_critical ("Got __MMS_HEADER_MAX: 0x%02X. Returning False", h);
              return FALSE;
            }
          else {
              DBG ("Header 0x%02X is not handled in decoding. Skipping....", h);
              continue;
            }
        }

      DBG ("saw header of type 0x%02X", h);

      /* Unsupported header, skip */
      if (entries[h].data == NULL)
        continue;

      /* Skip multiply present headers unless explicitly requested */
      if ((entries[h].flags & HEADER_FLAG_MARKED) &&
          !(entries[h].flags & HEADER_FLAG_ALLOW_MULTI))
        continue;

      DBG ("running handler for type 0x%02X", h);

      /* Parse the header */
      if (handler (iter, entries[h].data) == FALSE)
        {
          DBG ("handler %p for type 0x%02X returned false", handler, h);
          return FALSE;
        }

      DBG ("handler for type 0x%02X was success", h);

      entries[h].pos = i;
      entries[h].flags |= HEADER_FLAG_MARKED;
    }

  for (i = 0; i < __MMS_HEADER_MAX + 1; i++)
    if ((entries[i].flags & HEADER_FLAG_MANDATORY) &&
        !(entries[i].flags & HEADER_FLAG_MARKED))
      {
        DBG ("header 0x%02X was mandatory but not marked", i);
        return FALSE;
      }

  /*
   * Here we check for header positions.  This function assumes that
   * headers marked with PRESET_POS are in the beginning of the message
   * and follow the same order as given in the va_arg list.  The headers
   * marked this way have to be contiguous.
   */
  for (i = 0; i < __MMS_HEADER_MAX + 1; i++)
    {
      int check_flags = HEADER_FLAG_PRESET_POS | HEADER_FLAG_MARKED;
      int expected_pos = 1;

      if ((entries[i].flags & check_flags) != check_flags)
        continue;

      va_start (args, orig_header);
      header = orig_header;

      while (header != MMS_HEADER_INVALID && header != i)
        {
          va_arg (args, int);
          va_arg (args, void *);

          if (entries[header].flags & HEADER_FLAG_MARKED)
            expected_pos += 1;

          header = va_arg (args, enum mms_header);
        }

      va_end (args);

      if (entries[i].pos != expected_pos)
        {
          DBG ("header 0x%02X was in position 0x%02X but expected in position 0x%02X", i, entries[i].pos, expected_pos);
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
decode_delivery_ind (struct wsp_header_iter *iter,
                     struct mms_message     *out)
{
  return mms_parse_headers (iter, MMS_HEADER_MMS_VERSION,
                            HEADER_FLAG_MANDATORY | HEADER_FLAG_PRESET_POS,
                            &out->version,
                            MMS_HEADER_MESSAGE_ID,
                            HEADER_FLAG_MANDATORY, &out->di.msgid,
                            MMS_HEADER_TO,
                            HEADER_FLAG_MANDATORY | HEADER_FLAG_ALLOW_MULTI,
                            &out->di.to,
                            MMS_HEADER_DATE,
                            HEADER_FLAG_MANDATORY, &out->di.date,
                            MMS_HEADER_STATUS,
                            HEADER_FLAG_MANDATORY, &out->di.dr_status,
                            MMS_HEADER_INVALID);
}

static gboolean
decode_notification_ind (struct wsp_header_iter *iter,
                         struct mms_message     *out)
{
  return mms_parse_headers (iter, MMS_HEADER_TRANSACTION_ID,
                            HEADER_FLAG_MANDATORY,
                            &out->transaction_id,
                            MMS_HEADER_MMS_VERSION,
                            HEADER_FLAG_MANDATORY,
                            &out->version,
                            MMS_HEADER_FROM,
                            0, &out->ni.from,
                            MMS_HEADER_SUBJECT,
                            0, &out->ni.subject,
                            MMS_HEADER_MESSAGE_CLASS,
                            HEADER_FLAG_MANDATORY, &out->ni.cls,
                            MMS_HEADER_MESSAGE_SIZE,
                            HEADER_FLAG_MANDATORY, &out->ni.size,
                            MMS_HEADER_EXPIRY,
                            HEADER_FLAG_MANDATORY, &out->ni.expiry,
                            MMS_HEADER_CONTENT_LOCATION,
                            HEADER_FLAG_MANDATORY, &out->ni.location,
                            MMS_HEADER_INVALID);
}

static const char *
decode_attachment_charset (const unsigned char *pdu,
                           unsigned int         len)
{
  struct wsp_parameter_iter iter;
  struct wsp_parameter param;

  wsp_parameter_iter_init (&iter, pdu, len);

  while (wsp_parameter_iter_next (&iter, &param))
    if (param.type == WSP_PARAMETER_TYPE_CHARSET)
      return param.text;

  return NULL;
}

static gboolean
extract_content_id (struct wsp_header_iter *iter,
                    void                   *user)
{
  char **out = user;
  const unsigned char *p;
  unsigned int l;
  const char *text;

  p = wsp_header_iter_get_val (iter);
  l = wsp_header_iter_get_val_len (iter);

  /*
   * Some MMSes do not encode a filename for the attachment. If this happens,
   * the value of iter will be empty. Rather than make this a chat applicaton's
   * problem, I am adding a random filename here.
   */

  if (l == 0)
    {
      DBG ("Extracted content ID is empty, manually adding random id...");
      *out = g_uuid_string_random ();
    }
  else {
      if (wsp_header_iter_get_val_type (iter) != WSP_VALUE_TYPE_TEXT)
        return FALSE;

      text = wsp_decode_quoted_string (p, l, NULL);

      if (text == NULL)
        return FALSE;

      *out = g_strdup (text);
    }

  DBG ("extracted content-id %s\n", *out);

  return TRUE;
}

static gboolean
attachment_parse_headers (struct wsp_header_iter *iter,
                          struct mms_attachment  *part)
{
  while (wsp_header_iter_next (iter))
    {
      const unsigned char *hdr = wsp_header_iter_get_hdr (iter);
      unsigned char h;

      /* Skip application headers */
      if (wsp_header_iter_get_hdr_type (iter) !=
          WSP_HEADER_TYPE_WELL_KNOWN)
        continue;

      h = hdr[0] & 0x7f;

      switch (h)
        {
        case MMS_PART_HEADER_CONTENT_ID:
          if (extract_content_id (iter, &part->content_id)
              == FALSE)
            return FALSE;
          break;
        case MMS_PART_HEADER_CONTENT_LOCATION:
          break;
        default:
          break;
        }
    }

  return TRUE;
}

static void
free_attachment (gpointer data,
                 gpointer user_data)
{
  struct mms_attachment *attach = data;

  g_free (attach->content_type);
  g_free (attach->content_id);

  g_free (attach);
}

static gboolean
mms_parse_attachments (struct wsp_header_iter *iter,
                       struct mms_message     *out)
{
  struct wsp_multipart_iter mi;
  const void *ct;
  unsigned int ct_len;
  unsigned int consumed;

  if (wsp_multipart_iter_init (&mi, iter, &ct, &ct_len) == FALSE)
    return FALSE;

  while (wsp_multipart_iter_next (&mi) == TRUE)
    {
      struct mms_attachment *part;
      struct wsp_header_iter hi;
      const void *mimetype;
      const char *charset;

      ct = wsp_multipart_iter_get_content_type (&mi);
      ct_len = wsp_multipart_iter_get_content_type_len (&mi);

      if (wsp_decode_content_type (ct, ct_len, &mimetype,
                                   &consumed, NULL) == FALSE)
        return FALSE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"
      charset = decode_attachment_charset (ct + consumed,
                                           ct_len - consumed);
#pragma GCC diagnostic pop
      wsp_header_iter_init (&hi, wsp_multipart_iter_get_hdr (&mi),
                            wsp_multipart_iter_get_hdr_len (&mi),
                            0);

      part = g_try_new0 (struct mms_attachment, 1);
      if (part == NULL)
        return FALSE;

      if (attachment_parse_headers (&hi, part) == FALSE)
        {
          free_attachment (part, NULL);
          return FALSE;
        }

      if (wsp_header_iter_at_end (&hi) == FALSE)
        {
          free_attachment (part, NULL);
          return FALSE;
        }

      if (charset == NULL)
        part->content_type = g_strdup (mimetype);
      else
        part->content_type = g_strconcat (mimetype, ";charset=",
                                          charset, NULL);

      part->length = wsp_multipart_iter_get_body_len (&mi);
      part->offset = (const unsigned char *)
                     wsp_multipart_iter_get_body (&mi) -
                     wsp_header_iter_get_pdu (iter);

      out->attachments = g_slist_prepend (out->attachments, part);
    }

  if (wsp_multipart_iter_close (&mi, iter) == FALSE)
    return FALSE;

  out->attachments = g_slist_reverse (out->attachments);

  return TRUE;
}

static gboolean
decode_retrieve_conf (struct wsp_header_iter *iter,
                      struct mms_message     *out)
{
  if (mms_parse_headers (iter, MMS_HEADER_TRANSACTION_ID,
                         0, &out->transaction_id,
                         MMS_HEADER_MMS_VERSION,
                         HEADER_FLAG_MANDATORY,
                         &out->version,
                         MMS_HEADER_FROM,
                         0, &out->rc.from,
                         MMS_HEADER_TO,
                         HEADER_FLAG_ALLOW_MULTI, &out->rc.to,
                         MMS_HEADER_SUBJECT,
                         0, &out->rc.subject,
                         MMS_HEADER_MESSAGE_CLASS,
                         0, &out->rc.cls,
                         MMS_HEADER_PRIORITY,
                         0, &out->rc.priority,
                         MMS_HEADER_MESSAGE_ID,
                         0, &out->rc.msgid,
                         MMS_HEADER_DATE,
                         HEADER_FLAG_MANDATORY, &out->rc.date,
                         MMS_HEADER_INVALID) == FALSE)
    return FALSE;

  if (wsp_header_iter_at_end (iter) == TRUE)
    return TRUE;

  if (wsp_header_iter_is_multipart (iter) == FALSE)
    return FALSE;

  if (mms_parse_attachments (iter, out) == FALSE)
    return FALSE;

  if (wsp_header_iter_at_end (iter) == FALSE)
    return FALSE;

  return TRUE;
}

static gboolean
decode_send_conf (struct wsp_header_iter *iter,
                  struct mms_message     *out)
{
  return mms_parse_headers (iter, MMS_HEADER_TRANSACTION_ID,
                            HEADER_FLAG_MANDATORY,
                            &out->transaction_id,
                            MMS_HEADER_MMS_VERSION,
                            HEADER_FLAG_MANDATORY,
                            &out->version,
                            MMS_HEADER_RESPONSE_STATUS,
                            HEADER_FLAG_MANDATORY, &out->sc.rsp_status,
                            MMS_HEADER_MESSAGE_ID,
                            0, &out->sc.msgid,
                            MMS_HEADER_INVALID);
}

static gboolean
decode_send_req (struct wsp_header_iter *iter,
                 struct mms_message     *out)
{
  if (mms_parse_headers (iter, MMS_HEADER_TRANSACTION_ID,
                         HEADER_FLAG_MANDATORY,
                         &out->transaction_id,
                         MMS_HEADER_MMS_VERSION,
                         HEADER_FLAG_MANDATORY,
                         &out->version,
                         MMS_HEADER_TO,
                         HEADER_FLAG_ALLOW_MULTI, &out->sr.to,
                         MMS_HEADER_SUBJECT,
                         0, &out->sr.subject,
                         MMS_HEADER_INVALID) == FALSE)
    return FALSE;

  if (wsp_header_iter_at_end (iter) == TRUE)
    return TRUE;

  if (wsp_header_iter_is_multipart (iter) == FALSE)
    return FALSE;

  if (mms_parse_attachments (iter, out) == FALSE)
    return FALSE;

  if (wsp_header_iter_at_end (iter) == FALSE)
    return FALSE;

  return TRUE;
}

#define CHECK_WELL_KNOWN_HDR(hdr)             \
  if (wsp_header_iter_next (&iter) == FALSE)  \
  return FALSE;                               \
                                              \
  if (wsp_header_iter_get_hdr_type (&iter) != \
      WSP_HEADER_TYPE_WELL_KNOWN)             \
  return FALSE;                               \
                                              \
  p = wsp_header_iter_get_hdr (&iter);        \
                                              \
  if ((p[0] & 0x7f) != hdr)                   \
  return FALSE                                \

gboolean
mms_message_decode (const unsigned char *pdu,
                    unsigned int         len,
                    struct mms_message  *out)
{
  unsigned int flags = 0;
  struct wsp_header_iter iter;
  const unsigned char *p;
  unsigned char octet;

  memset (out, 0, sizeof(*out));

  flags |= WSP_HEADER_ITER_FLAG_REJECT_CP;
  flags |= WSP_HEADER_ITER_FLAG_DETECT_MMS_MULTIPART;
  wsp_header_iter_init (&iter, pdu, len, flags);

  DBG ("about to check well known");

  CHECK_WELL_KNOWN_HDR (MMS_HEADER_MESSAGE_TYPE);

  DBG ("about to extract short");

  if (extract_short (&iter, &octet) == FALSE)
    return FALSE;

  DBG ("octet %u", octet);

  if (octet < MMS_MESSAGE_TYPE_SEND_REQ ||
      octet > MMS_MESSAGE_TYPE_DELIVERY_IND)
    return FALSE;

  out->type = octet;

  switch (out->type)
    {
    case MMS_MESSAGE_TYPE_SEND_REQ:
      DBG ("MMS_MESSAGE_TYPE_SEND_REQ");
      return decode_send_req (&iter, out);
    case MMS_MESSAGE_TYPE_SEND_CONF:
      DBG ("MMS_MESSAGE_TYPE_SEND_CONF");
      return decode_send_conf (&iter, out);
    case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
      DBG ("MMS_MESSAGE_TYPE_NOTIFICATION_IND");
      return decode_notification_ind (&iter, out);
    case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
      DBG ("MMS_MESSAGE_TYPE_NOTIFYRESP_IND");
      DBG ("Do not know how to decode");
      return FALSE;
    case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
      DBG ("MMS_MESSAGE_TYPE_RETRIEVE_CONF");
      return decode_retrieve_conf (&iter, out);
    case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
      DBG ("MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND");
      DBG ("Do not know how to decode");
      return FALSE;
    case MMS_MESSAGE_TYPE_DELIVERY_IND:
      DBG ("MMS_MESSAGE_TYPE_DELIVERY_IND");
      return decode_delivery_ind (&iter, out);
    default:
      g_warning ("Unhandled case");
      return FALSE;
    }

  return FALSE;
}

void
mms_message_free (struct mms_message *msg)
{
  switch (msg->type)
    {
    case MMS_MESSAGE_TYPE_SEND_REQ:
      g_free (msg->sr.to);
      g_free (msg->sr.content_type);
      g_free (msg->sr.datestamp);
      g_free (msg->sr.subject);
      g_free (msg->sr.delivery_recipients);
      break;
    case MMS_MESSAGE_TYPE_SEND_CONF:
      g_free (msg->sc.msgid);
      break;
    case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
      g_free (msg->ni.from);
      g_free (msg->ni.subject);
      g_free (msg->ni.cls);
      g_free (msg->ni.location);
      break;
    case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
      break;
    case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
      g_free (msg->rc.from);
      g_free (msg->rc.to);
      g_free (msg->rc.subject);
      g_free (msg->rc.cls);
      g_free (msg->rc.priority);
      g_free (msg->rc.msgid);
      g_free (msg->rc.datestamp);
      break;
    case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
      break;
    case MMS_MESSAGE_TYPE_DELIVERY_IND:
      g_free (msg->di.msgid);
      g_free (msg->di.to);
      break;
    default:
      g_warning ("Unhandled case");
      break;
    }

  g_free (msg->uuid);
  g_free (msg->path);
  g_free (msg->transaction_id);

  if (msg->attachments != NULL)
    {
      g_slist_foreach (msg->attachments, free_attachment, NULL);
      g_slist_free (msg->attachments);
    }

  g_free (msg);
}

static void
fb_init (struct file_buffer *fb,
         int                 fd)
{
  fb->size = 0;
  fb->fsize = 0;
  fb->fd = fd;
}

static gboolean
fb_flush (struct file_buffer *fb)
{
  unsigned int size;
  ssize_t len;

  if (fb->size == 0)
    return TRUE;

  len = write (fb->fd, fb->buf, fb->size);
  if (len < 0)
    return FALSE;

  size = len;

  if (size != fb->size)
    return FALSE;

  fb->fsize += size;

  fb->size = 0;

  return TRUE;
}

static unsigned int
fb_get_file_size (struct file_buffer *fb)
{
  return fb->fsize + fb->size;
}

static void *
fb_request (struct file_buffer *fb,
            unsigned int        count)
{
  if (fb->size + count < FB_SIZE)
    {
      void *ptr = fb->buf + fb->size;
      fb->size += count;
      return ptr;
    }

  if (fb_flush (fb) == FALSE)
    return NULL;

  if (count > FB_SIZE)
    return NULL;

  fb->size = count;

  return fb->buf;
}

static void *
fb_request_field (struct file_buffer *fb,
                  unsigned char       token,
                  unsigned int        len)
{
  unsigned char *ptr;

  ptr = fb_request (fb, len + 1);
  if (ptr == NULL)
    return NULL;

  ptr[0] = token | 0x80;

  return ptr + 1;
}

static gboolean
fb_copy (struct file_buffer *fb,
         const void         *buf,
         unsigned int        c)
{
  unsigned int written;
  ssize_t len;

  if (fb_flush (fb) == FALSE)
    return FALSE;

  len = TFR (write (fb->fd, buf, c));
  if (len < 0)
    return FALSE;

  written = len;

  if (written != c)
    return FALSE;

  fb->fsize += written;

  return TRUE;
}

static gboolean
fb_put_value_length (struct file_buffer *fb,
                     unsigned int        val)
{
  unsigned int count;

  if (fb->size + MAX_ENC_VALUE_BYTES > FB_SIZE)
    if (fb_flush (fb) == FALSE)
      return FALSE;

  if (wsp_encode_value_length (val, fb->buf + fb->size, FB_SIZE - fb->size,
                               &count) == FALSE)
    return FALSE;

  fb->size += count;

  return TRUE;
}

static gboolean
fb_put_uintvar (struct file_buffer *fb,
                unsigned int        val)
{
  unsigned int count;

  if (fb->size + MAX_ENC_VALUE_BYTES > FB_SIZE)
    if (fb_flush (fb) == FALSE)
      return FALSE;

  if (wsp_encode_uintvar (val, fb->buf + fb->size, FB_SIZE - fb->size,
                          &count) == FALSE)
    return FALSE;

  fb->size += count;

  return TRUE;
}

static gboolean
encode_short (struct file_buffer *fb,
              enum mms_header     header,
              void               *user)
{
  char *ptr;
  unsigned int *wk = user;

  ptr = fb_request_field (fb, header, 1);
  if (ptr == NULL)
    return FALSE;

  *ptr = *wk | 0x80;

  return TRUE;
}

static gboolean
encode_from (struct file_buffer *fb,
             enum mms_header     header,
             void               *user)
{
  char *ptr;
  char **text = user;

  if (strlen (*text) > 0)
    return FALSE;

  /* From: header token + value length + Insert-address-token */
  ptr = fb_request_field (fb, header, 2);
  if (ptr == NULL)
    return FALSE;

  ptr[0] = 1;
  ptr[1] = 129;

  return TRUE;
}

static gboolean
encode_text (struct file_buffer *fb,
             enum mms_header     header,
             void               *user)
{
  char *ptr;
  char **text = user;
  unsigned int len;

  len = strlen (*text) + 1;

  //Do not encode anything if the test is empty
  if (len == 1)
    return TRUE;

  ptr = fb_request_field (fb, header, len);
  if (ptr == NULL)
    return FALSE;

  strcpy (ptr, *text);

  return TRUE;
}

static gboolean
encode_quoted_string (struct file_buffer *fb,
                      enum mms_header     header,
                      void               *user)
{
  char *ptr;
  char **text = user;
  unsigned int len;

  len = strlen (*text) + 1;

  ptr = fb_request_field (fb, header, len + 3);
  if (ptr == NULL)
    return FALSE;

  ptr[0] = '"';
  ptr[1] = '<';
  strcpy (ptr + 2, *text);
  ptr[len + 1] = '>';
  ptr[len + 2] = '\0';

  return TRUE;
}

static gboolean
encode_text_array_element (struct file_buffer *fb,
                           enum mms_header     header,
                           void               *user)
{
  char **text = user;
  char **tos;
  int i;

  tos = g_strsplit (*text, ",", 0);

  for (i = 0; tos[i] != NULL; i++)
    if (encode_text (fb, header, &tos[i]) == FALSE)
      {
        g_strfreev (tos);
        return FALSE;
      }

  g_strfreev (tos);

  return TRUE;
}

static gboolean
encode_content_type (struct file_buffer *fb,
                     enum mms_header     header,
                     void               *user)
{
  char *ptr;
  char **hdr = user;
  unsigned int len;
  unsigned int ct;
  unsigned int ct_len;
  unsigned int type_len;
  unsigned int start_len;
  const char *ct_str;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
  const char *uninitialized_var (type);
  const char *uninitialized_var (start);
#pragma GCC diagnostic pop
  struct wsp_text_header_iter iter;

  if (wsp_text_header_iter_init (&iter, *hdr) == FALSE)
    return FALSE;

  if (g_ascii_strcasecmp ("Content-Type",
                          wsp_text_header_iter_get_key (&iter)) != 0)
    return FALSE;

  ct_str = wsp_text_header_iter_get_value (&iter);

  if (wsp_get_well_known_content_type (ct_str, &ct) == TRUE)
    ct_len = 1;
  else
    ct_len = strlen (ct_str) + 1;

  len = ct_len;

  type_len = 0;
  start_len = 0;

  while (wsp_text_header_iter_param_next (&iter) == TRUE)
    {
      if (g_ascii_strcasecmp ("type",
                              wsp_text_header_iter_get_key (&iter)) == 0)
        {
          type = wsp_text_header_iter_get_value (&iter);
          type_len = strlen (type) + 1;
          len += 1 + type_len;
        }
      else if (g_ascii_strcasecmp ("start",
                                   wsp_text_header_iter_get_key (&iter)) == 0)
        {
          start = wsp_text_header_iter_get_value (&iter);
          start_len = strlen (start) + 1;
          len += 1 + start_len;
        }
    }

  if (len == 1)
    return encode_short (fb, header, &ct);

  ptr = fb_request (fb, 1);
  if (ptr == NULL)
    return FALSE;

  *ptr = header | 0x80;

  /* Encode content type value length */
  if (fb_put_value_length (fb, len) == FALSE)
    return FALSE;

  /* Encode content type including parameters */
  ptr = fb_request (fb, ct_len);
  if (ptr == NULL)
    return FALSE;

  if (ct_len == 1)
    *ptr = ct | 0x80;
  else
    strcpy (ptr, ct_str);

  if (type_len > 0)
    {
      ptr = fb_request_field (fb, WSP_PARAMETER_TYPE_CONTENT_TYPE,
                              type_len);
      if (ptr == NULL)
        return FALSE;

      strcpy (ptr, type);
    }

  if (start_len > 0)
    {
      ptr = fb_request_field (fb, WSP_PARAMETER_TYPE_START_DEFUNCT,
                              start_len);
      if (ptr == NULL)
        return FALSE;

      strcpy (ptr, start);
    }

  return TRUE;
}

static header_encoder
encoder_for_type (enum mms_header header)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
  //Refer to enum mms_header if you need to add headers
  switch (header)
    {
    case MMS_HEADER_BCC:
      return NULL;
    case MMS_HEADER_CC:
      return NULL;
    case MMS_HEADER_CONTENT_LOCATION:
      return NULL;
    case MMS_HEADER_CONTENT_TYPE:
      return encode_content_type;
    case MMS_HEADER_DATE:
      return NULL;
    case MMS_HEADER_DELIVERY_REPORT:
      return encode_short;
    case MMS_HEADER_DELIVERY_TIME:
      return NULL;
    case MMS_HEADER_EXPIRY:
      return NULL;
    case MMS_HEADER_FROM:
      return encode_from;
    case MMS_HEADER_MESSAGE_CLASS:
      return NULL;
    case MMS_HEADER_MESSAGE_ID:
      return NULL;
    case MMS_HEADER_MESSAGE_TYPE:
      return encode_short;
    case MMS_HEADER_MMS_VERSION:
      return encode_short;
    case MMS_HEADER_MESSAGE_SIZE:
      return NULL;
    case MMS_HEADER_PRIORITY:
      return NULL;
    case MMS_HEADER_READ_REPLY:
      return NULL;
    case MMS_HEADER_REPORT_ALLOWED:
      return NULL;
    case MMS_HEADER_RESPONSE_STATUS:
      return NULL;
    case MMS_HEADER_RESPONSE_TEXT:
      return NULL;
    case MMS_HEADER_RETRIEVE_STATUS:
      return NULL;
    case MMS_HEADER_RETRIEVE_TEXT:
      return NULL;
    case MMS_HEADER_READ_STATUS:
      return NULL;
    case MMS_HEADER_SENDER_VISIBILITY:
      return NULL;
    case MMS_HEADER_STATUS:
      return encode_short;
    case MMS_HEADER_SUBJECT:
      return encode_text;
    case MMS_HEADER_TO:
      return encode_text_array_element;
    case MMS_HEADER_TRANSACTION_ID:
      return encode_text;
    case MMS_HEADER_INVALID:
    case __MMS_HEADER_MAX:
    default:
      return NULL;
    }
#pragma GCC diagnostic pop

  return NULL;
}

static gboolean
mms_encode_send_req_part_header (struct mms_attachment *part,
                                 struct file_buffer    *fb)
{
  char *ptr;
  unsigned int len;
  unsigned int ct;
  unsigned int ct_len;
  unsigned int cs_len;
  const char *ct_str;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
  const char *uninitialized_var (cs_str);
#pragma GCC diagnostic pop
  unsigned int ctp_len;
  unsigned int cid_len;
  unsigned char ctp_val[MAX_ENC_VALUE_BYTES];
  unsigned char cs_val[MAX_ENC_VALUE_BYTES];
  unsigned int cs;
  struct wsp_text_header_iter iter;

  /*
   * Compute Headers length: content-type [+ params] [+ content-id]
   * ex. : "Content-Type:text/plain; charset=us-ascii"
   */
  if (wsp_text_header_iter_init (&iter, part->content_type) == FALSE)
    return FALSE;

  if (g_ascii_strcasecmp ("Content-Type",
                          wsp_text_header_iter_get_key (&iter)) != 0)
    return FALSE;

  ct_str = wsp_text_header_iter_get_value (&iter);

  if (wsp_get_well_known_content_type (ct_str, &ct) == TRUE)
    ct_len = 1;
  else
    ct_len = strlen (ct_str) + 1;

  len = ct_len;

  cs_len = 0;

  while (wsp_text_header_iter_param_next (&iter) == TRUE)
    {
      const char *key = wsp_text_header_iter_get_key (&iter);

      if (g_ascii_strcasecmp ("charset", key) == 0)
        {
          cs_str = wsp_text_header_iter_get_value (&iter);
          if (cs_str == NULL)
            return FALSE;

          len += 1;

          if (wsp_get_well_known_charset (cs_str, &cs) == FALSE)
            return FALSE;

          if (wsp_encode_integer (cs, cs_val, MAX_ENC_VALUE_BYTES,
                                  &cs_len) == FALSE)
            return FALSE;

          len += cs_len;
        }
    }

  if (wsp_encode_value_length (len, ctp_val, MAX_ENC_VALUE_BYTES,
                               &ctp_len) == FALSE)
    return FALSE;

  len += ctp_len;

  /* Compute content-id header length : token + (Quoted String) */
  if (part->content_id != NULL)
    {
      cid_len = 1 + strlen (part->content_id) + 3 + 1;
      len += cid_len;
    }
  else
    cid_len = 0;

  /* Encode total headers length */
  if (fb_put_uintvar (fb, len) == FALSE)
    return FALSE;

  /* Encode data length */
  if (fb_put_uintvar (fb, part->length) == FALSE)
    return FALSE;

  /* Encode content-type */
  ptr = fb_request (fb, ctp_len);
  if (ptr == NULL)
    return FALSE;

  memcpy (ptr, &ctp_val, ctp_len);

  ptr = fb_request (fb, ct_len);
  if (ptr == NULL)
    return FALSE;

  if (ct_len == 1)
    ptr[0] = ct | 0x80;
  else
    strcpy (ptr, ct_str);

  /* Encode "charset" param */
  if (cs_len > 0)
    {
      ptr = fb_request_field (fb, WSP_PARAMETER_TYPE_CHARSET, cs_len);
      if (ptr == NULL)
        return FALSE;

      memcpy (ptr, &cs_val, cs_len);
    }

  /* Encode content-id */
  if (part->content_id != NULL)
    if (encode_quoted_string (fb, MMS_PART_HEADER_CONTENT_ID,
                              &part->content_id) == FALSE)
      return FALSE;

  return TRUE;
}

static gboolean
mms_encode_send_req_part (struct mms_attachment *part,
                          struct file_buffer    *fb)
{
  if (mms_encode_send_req_part_header (part, fb) == FALSE)
    return FALSE;

  part->offset = fb_get_file_size (fb);

  return fb_copy (fb, part->data, part->length);
}

static gboolean
mms_encode_headers (struct file_buffer *fb,
                    enum mms_header     orig_header,
                    ...)
{
  va_list args;
  void *data;
  enum mms_header header;
  header_encoder encoder;

  va_start (args, orig_header);
  header = orig_header;

  while (header != MMS_HEADER_INVALID)
    {
      data = va_arg (args, void *);

      encoder = encoder_for_type (header);
      if (encoder == NULL)
        return FALSE;

      if (data && encoder (fb, header, data) == FALSE)
        return FALSE;

      header = va_arg (args, enum mms_header);
    }

  va_end (args);

  return TRUE;
}

static gboolean
mms_encode_notify_resp_ind (struct mms_message *msg,
                            struct file_buffer *fb)
{
  //Order Matters when you encode headers!
  //Refer to: OMA-WAP-MMS-ENC-V1_1-20021030-C, Table 1
  //Note that the order below matches the order in Table 1
  if (mms_encode_headers (fb, MMS_HEADER_MESSAGE_TYPE, &msg->type,
                          MMS_HEADER_TRANSACTION_ID, &msg->transaction_id,
                          MMS_HEADER_MMS_VERSION, &msg->version,
                          MMS_HEADER_STATUS, &msg->nri.notify_status,
                          MMS_HEADER_INVALID) == FALSE)
    return FALSE;

  return fb_flush (fb);
}

static gboolean
mms_encode_send_req (struct mms_message *msg,
                     struct file_buffer *fb)
{
  const char *empty_from = "";
  GSList *item;
  enum mms_message_value_bool dr;

  if (msg->sr.dr == TRUE)
    dr = MMS_MESSAGE_VALUE_BOOL_YES;
  else
    dr = MMS_MESSAGE_VALUE_BOOL_NO;
  //Order Matters when you encode headers!
  //Refer to: OMA-WAP-MMS-ENC-V1_1-20021030-C, Table 1
  //Note that the order below matches the order in Table 1
  if (mms_encode_headers (fb, MMS_HEADER_MESSAGE_TYPE, &msg->type,
                          MMS_HEADER_TRANSACTION_ID, &msg->transaction_id,
                          MMS_HEADER_MMS_VERSION, &msg->version,
                          MMS_HEADER_FROM, &empty_from,
                          MMS_HEADER_TO, &msg->sr.to,
                          MMS_HEADER_SUBJECT, &msg->sr.subject,
                          MMS_HEADER_DELIVERY_REPORT, &dr,
                          MMS_HEADER_CONTENT_TYPE, &msg->sr.content_type,
                          MMS_HEADER_INVALID) == FALSE)
    return FALSE;

  if (msg->attachments == NULL)
    goto done;

  if (fb_put_uintvar (fb, g_slist_length (msg->attachments)) == FALSE)
    return FALSE;

  for (item = msg->attachments; item != NULL; item = g_slist_next (item))
    if (mms_encode_send_req_part (item->data, fb) == FALSE)
      return FALSE;

 done:
  return fb_flush (fb);
}

gboolean
mms_message_encode (struct mms_message *msg,
                    int                 fd)
{
  struct file_buffer fb;

  fb_init (&fb, fd);

  switch (msg->type)
    {
    case MMS_MESSAGE_TYPE_SEND_REQ:
      return mms_encode_send_req (msg, &fb);
    case MMS_MESSAGE_TYPE_SEND_CONF:
    case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
      return FALSE;
    case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
      return mms_encode_notify_resp_ind (msg, &fb);
    case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
    case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
    case MMS_MESSAGE_TYPE_DELIVERY_IND:
      return FALSE;
    default:
      g_warning ("Unhandled case");
      return FALSE;
    }

  return FALSE;
}

const char *
mms_message_status_get_string (enum mms_message_status status)
{
  switch (status)
    {
    case MMS_MESSAGE_STATUS_DOWNLOADED:
      return "downloaded";
    case MMS_MESSAGE_STATUS_RECEIVED:
      return "received";
    case MMS_MESSAGE_STATUS_READ:
      return "read";
    case MMS_MESSAGE_STATUS_SENT:
      return "sent";
    case MMS_MESSAGE_STATUS_DRAFT:
      return "draft";
    case MMS_MESSAGE_STATUS_DELIVERED:
      return "delivered";
    case MMS_MESSAGE_STATUS_SENDING_FAILED:
      return "sending_failed";
    default:
      g_warning ("Unhandled case");
      return NULL;
    }

  return NULL;
}

const char *
message_rsp_status_to_string (
  enum mms_message_rsp_status status)
{
  switch (status)
    {
    case MMS_MESSAGE_RSP_STATUS_OK:
      return "ok";
    case MMS_MESSAGE_RSP_STATUS_ERR_UNSUPPORTED_MESSAGE:
      return "error-unsupported-message";
    case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_FAILURE:
      return "error-transient-failure";
    case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_NETWORK_PROBLEM:
      return "error-transient-network-problem";
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_FAILURE:
      return "error-permanent-failure";
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SERVICE_DENIED:
      return "error-permanent-service-denied";
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_MESSAGE_FORMAT_CORRUPT:
      return "error-permanent-message-format-corrupt";
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SENDING_ADDRESS_UNRESOLVED:
      return "error-permanent-sending-address-unresolved";
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_CONTENT_NOT_ACCEPTED:
      return "error-permanent-content-not-accepted";
    case MMS_MESSAGE_RSP_STATUS_ERR_PERM_LACK_OF_PREPAID:
      return "error-permanent-lack-of-prepaid";
    default:
      g_warning ("Unhandled case");
      return NULL;
    }

  return NULL;
}

// mms_message_create_smil() was primarily done by
// sending myself texts from the Android AOSP Messaging app
// and looking at how they encode their SMIL, while looking at:
// https://www.w3.org/TR/SMIL20/
// to see what it all means. I am aware SMIL 2.0 is outdated,
// but the MMS spec says to use SMIL 2.0. *shrug*
// You will have to forgive me for mms_message_create_smil()
// being fairly crude.

char *
mms_message_create_smil (GVariant *attachments)
{
  GString *smil, *smil_body;
  gchar *smil_body_to_attach;
  gchar *smil_to_return;
  g_autoptr(GVariant) single_attachment = NULL;
  GVariantIter iter;
  gboolean contains_only_image_video_plaintext = TRUE;
  gboolean contains_image_or_video = FALSE;
  gboolean contains_text = FALSE;
  gboolean contains_only_text = TRUE;

  g_variant_iter_init (&iter, attachments);

  smil = g_string_new ("<smil><head><layout><root-layout");
  smil_body = g_string_new (NULL);

  while ((single_attachment = g_variant_iter_next_value (&iter)))
    {
      g_autofree char *content_id = NULL;
      g_autofree char *mime_type = NULL;
      g_autofree char *file_path = NULL;

      g_variant_get (single_attachment, "(sss)", &content_id, &mime_type, &file_path);

      if (!g_str_match_string ("image", mime_type, FALSE))
        if (!g_str_match_string ("video", mime_type, FALSE))
          if (!g_str_match_string ("text", mime_type, FALSE))
            {
              DBG ("This MMS has something other than images, videos, or plaintext");
              contains_only_image_video_plaintext = FALSE;
              if (!g_str_match_string ("audio", mime_type, FALSE))
                {
                  DBG ("This MMS has non-media files, SMIL cannot be created for it.");
                  g_string_free (smil, TRUE);
                  g_string_free (smil_body, TRUE);
                  return g_strdup ("");
                }
            }

      // After going through the SMIL Standard, the "dur" attribute is not
      // strictly required:
      // https://www.w3.org/TR/SMIL20/smil-timing.html#Timing-BasicTiming
      // https://www.w3.org/AudioVideo/RA-examples.html
      //
      // Android puts the "dur" element in no matter what.
      // I suspect that there is a reason for this (compatibility
      // with some misbehaving MMS client?)
      // Android puts a generic dur="5000ms" for images, but puts
      // the exact dur for audio/video.
      //
      // I don't want to add a bunch if libraries just to figure
      // out the length of an audio/video file, so I am just going
      // to set the duration to an hour (36000000ms) for all elements
      // (as I doubt any MMS payload will have an hour long audio
      // or video).

      if (g_str_match_string ("image", mime_type, FALSE))
        {
          contains_image_or_video = TRUE;
          g_string_append (smil_body, "<par dur=\"5000ms\"><img src=\"");
          g_string_append (smil_body, content_id);
          g_string_append (smil_body, "\" region=\"Image\"/></par>");
        }
      if (g_str_match_string ("video", mime_type, FALSE))
        {
          contains_image_or_video = TRUE;
          g_string_append (smil_body, "<par dur=\"36000000ms\"><video src=\"");
          g_string_append (smil_body, content_id);
          g_string_append (smil_body, "\" dur=\"36000000ms\" region=\"Image\" /></par>");
        }
      if (g_str_match_string ("text", mime_type, FALSE))
        {
          if (g_str_match_string ("vcf", mime_type, FALSE))
            {
              DBG ("This MMS has something other than images, videos, or plaintext");
              contains_only_image_video_plaintext = FALSE;
              g_string_append (smil_body, "<par dur=\"5000ms\"><ref src=\"");
              g_string_append (smil_body, content_id);
              g_string_append (smil_body, "\" /></par>");
            }
          else {
              DBG ("This MMS has text");
              contains_text = TRUE;
              g_string_append (smil_body, "<par dur=\"5000ms\"><text src=\"");
              g_string_append (smil_body, content_id);
              g_string_append (smil_body, "\" region=\"Text\" /></par>");
            }
        }
      else {
          DBG ("This MMS has content other than text");
          contains_only_text = FALSE;
        }
      if (g_str_match_string ("audio", mime_type, FALSE))
        {
          g_string_append (smil_body, "<par dur=\"36000000ms\"><audio src=\"");
          g_string_append (smil_body, content_id);
          g_string_append (smil_body, "\" dur=\"36000000ms\" /></par>");
        }
    }
  smil_body_to_attach = g_string_free (smil_body, FALSE);

  if (contains_only_image_video_plaintext && !contains_only_text)
    {
      DBG ("This MMS only has Images, Videos, or plaintext");
      g_string_append (smil, " width=\"100%\" height=\"100%\"");
    }
  g_string_append (smil, "/>");

  if (contains_only_text)
    {
      DBG ("This MMS only has text");
      g_string_append (smil, "<region id=\"Text\" top=\"0\" left=\"0\" height=\"100%\" width=\"100%\"/>");
    }
  else if (contains_text && contains_image_or_video)
    {
      DBG ("This MMS has text with images or videos");
      g_string_append (smil, "<region id=\"Image\" fit=\"meet\" top=\"0\" left=\"0\" height=\"80%\" width=\"100%\"/><region id=\"Text\" top=\"80%\" left=\"0\" height=\"20%\" width=\"100%\"/>");
    }
  else if (contains_image_or_video)
    {
      DBG ("This MMS has images or videos");
      g_string_append (smil, "<region id=\"Image\" width=\"100%\" height=\"100%\" top=\"0%\" left=\"0%\" fit=\"meet\"/>");
    }
  g_string_append (smil, "</layout></head><body>");

  g_string_append (smil, smil_body_to_attach);
  g_free (smil_body_to_attach);

  g_string_append (smil, "</body></smil>");
  smil_to_return = g_string_free (smil, FALSE);
  return smil_to_return;
}
