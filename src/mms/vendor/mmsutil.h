/*
 * ---------------------------------------------------------------------
 * Vendored from mmsd-tng (https://gitlab.com/kop316/mmsd)
 * Upstream file:   src/mmsutil.h
 * Upstream commit: 341117141f8d30949fb1294cc71ee44af9b4c90f
 * Vendored on:     2026-07-02
 *
 * Local modifications (chan_modemmanager, src/mms/vendor/mmsutil.h):
 *   - Added `#include <glib.h>`, `#include <time.h>`, `#include <stddef.h>`
 *     below, for the same reason described in wsputil.h's provenance
 *     note: upstream relies on translation-unit include order (mms.h
 *     always included first) to make gboolean/time_t/size_t/GSList/
 *     GVariant visible; this vendor tree drops mms.h, so the header is
 *     made self-sufficient instead.
 *   - Wrapped the whole header in a `#ifndef CHAN_MM_MMS_VENDOR_MMSUTIL_H`
 *     include guard, for the same double-inclusion-safety reason given
 *     in wsputil.h's provenance note (mms_codec.h and mms_codec.c both
 *     end up including this header).
 *   - No other changes; every enum/struct/prototype below is verbatim
 *     upstream (this is upstream's real, self-contained type/API header
 *     for struct mms_message -- upstream's separate src/mms.h is a thin
 *     daemon-composition header that mostly just #includes plugin.h,
 *     service.h, store.h, log.h; none of that is used by mmsutil.c/
 *     wsputil.c and it is intentionally NOT vendored here).
 * ---------------------------------------------------------------------
 */

#ifndef CHAN_MM_MMS_VENDOR_MMSUTIL_H
#define CHAN_MM_MMS_VENDOR_MMSUTIL_H

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

#include <glib.h>
#include <time.h>
#include <stddef.h>

enum mms_message_type {
  MMS_MESSAGE_TYPE_SEND_REQ =                     128,
  MMS_MESSAGE_TYPE_SEND_CONF =                    129,
  MMS_MESSAGE_TYPE_NOTIFICATION_IND =             130,
  MMS_MESSAGE_TYPE_NOTIFYRESP_IND =               131,
  MMS_MESSAGE_TYPE_RETRIEVE_CONF =                132,
  MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND =              133,
  MMS_MESSAGE_TYPE_DELIVERY_IND =                 134,
};

enum mms_message_status {
  MMS_MESSAGE_STATUS_DOWNLOADED,
  MMS_MESSAGE_STATUS_RECEIVED,
  MMS_MESSAGE_STATUS_READ,
  MMS_MESSAGE_STATUS_SENT,
  MMS_MESSAGE_STATUS_SENDING_FAILED,
  MMS_MESSAGE_STATUS_DRAFT,
  MMS_MESSAGE_STATUS_DELIVERED
};

enum mms_message_rsp_status {
  MMS_MESSAGE_RSP_STATUS_OK =                                     128,
  MMS_MESSAGE_RSP_STATUS_ERR_UNSUPPORTED_MESSAGE =                136,
  MMS_MESSAGE_RSP_STATUS_ERR_TRANS_FAILURE =                      192,
  MMS_MESSAGE_RSP_STATUS_ERR_TRANS_NETWORK_PROBLEM =              195,
  MMS_MESSAGE_RSP_STATUS_ERR_PERM_FAILURE =                       224,
  MMS_MESSAGE_RSP_STATUS_ERR_PERM_SERVICE_DENIED =                225,
  MMS_MESSAGE_RSP_STATUS_ERR_PERM_MESSAGE_FORMAT_CORRUPT =        226,
  MMS_MESSAGE_RSP_STATUS_ERR_PERM_SENDING_ADDRESS_UNRESOLVED =    227,
  MMS_MESSAGE_RSP_STATUS_ERR_PERM_CONTENT_NOT_ACCEPTED =          229,
  MMS_MESSAGE_RSP_STATUS_ERR_PERM_LACK_OF_PREPAID =               235,
};

enum mms_message_retr_status {
  MMS_MESSAGE_RETR_STATUS_OK =                            128,
  MMS_MESSAGE_RETR_STATUS_ERR_TRANS_MIN =                 192,
  MMS_MESSAGE_RETR_STATUS_ERR_TRANS_FAILURE =             192,
  MMS_MESSAGE_RETR_STATUS_ERR_TRANS_MESSAGE_NOT_FOUND =   194,
  MMS_MESSAGE_RETR_STATUS_ERR_PERM_MIN =                  224,
  MMS_MESSAGE_RETR_STATUS_ERR_PERM_FAILURE =              224,
  MMS_MESSAGE_RETR_STATUS_ERR_PERM_SERVICE_DENIED =       225,
  MMS_MESSAGE_RETR_STATUS_ERR_PERM_MESSAGE_NOT_FOUND =    226,
  MMS_MESSAGE_RETR_STATUS_ERR_PERM_CONTENT_UNSUPPORTED =  227,
};

enum mms_message_read_status {
  MMS_MESSAGE_READ_STATUS_READ =                  128,
  MMS_MESSAGE_READ_STATUS_DELETED_UNREAD =        129,
};

enum mms_message_notify_status {
  MMS_MESSAGE_NOTIFY_STATUS_RETRIEVED =           129,
  MMS_MESSAGE_NOTIFY_STATUS_REJECTED =            130,
  MMS_MESSAGE_NOTIFY_STATUS_DEFERRED =            131,
  MMS_MESSAGE_NOTIFY_STATUS_UNRECOGNISED =        132,
};

enum mms_message_delivery_status {
  MMS_MESSAGE_DELIVERY_STATUS_EXPIRED =           128,
  MMS_MESSAGE_DELIVERY_STATUS_RETRIEVED =         129,
  MMS_MESSAGE_DELIVERY_STATUS_REJECTED =          130,
  MMS_MESSAGE_DELIVERY_STATUS_DEFERRED =          131,
  MMS_MESSAGE_DELIVERY_STATUS_UNRECOGNISED =      132,
  MMS_MESSAGE_DELIVERY_STATUS_INDETERMINATE =     133,
  MMS_MESSAGE_DELIVERY_STATUS_FORWARDED =         134,
  MMS_MESSAGE_DELIVERY_STATUS_UNREACHABLE =       135,
};

enum mms_message_sender_visibility {
  MMS_MESSAGE_SENDER_VISIBILITY_HIDE =            128,
  MMS_MESSAGE_SENDER_VISIBILITY_SHOW =            129,
};

enum mms_message_value_bool {
  MMS_MESSAGE_VALUE_BOOL_YES =                    128,
  MMS_MESSAGE_VALUE_BOOL_NO =                     129,
};

enum mms_message_version {
  MMS_MESSAGE_VERSION_1_0 =       0x90,
  MMS_MESSAGE_VERSION_1_1 =       0x91,
  MMS_MESSAGE_VERSION_1_2 =       0x92,
  MMS_MESSAGE_VERSION_1_3 =       0x93,
};

struct mms_notification_ind
{
  char *from;
  char *subject;
  char *cls;
  unsigned int size;
  time_t expiry;
  char *location;
  unsigned int status;
};

struct mms_retrieve_conf
{
  enum mms_message_status status;
  char *from;
  char *to;
  char *subject;
  char *cls;
  char *priority;
  char *msgid;
  time_t date;
  char *datestamp;
};

struct mms_send_req
{
  enum mms_message_status status;
  char *to;
  char *subject;
  time_t date;
  char *datestamp;
  char *content_type;
  gboolean dr;
  char *delivery_recipients;
};

struct mms_send_conf
{
  enum mms_message_rsp_status rsp_status;
  char *msgid;
};

struct mms_notification_resp_ind
{
  enum mms_message_notify_status notify_status;
};

struct mms_delivery_ind
{
  enum mms_message_delivery_status dr_status;
  char *msgid;
  char *to;
  time_t date;
};

struct mms_attachment
{
  unsigned char *data;
  size_t offset;
  size_t length;
  char *content_type;
  char *content_id;
};

struct mms_message
{
  enum mms_message_type type;
  char *uuid;
  char *path;
  char *transaction_id;
  guint message_registration_id;
  unsigned char version;
  GSList *attachments;
  union
  {
    struct mms_notification_ind ni;
    struct mms_retrieve_conf rc;
    struct mms_send_req sr;
    struct mms_send_conf sc;
    struct mms_notification_resp_ind nri;
    struct mms_delivery_ind di;
  };
};

char *mms_content_type_get_param_value (const char *content_type,
                                        const char *param_name);
gboolean mms_message_decode (const unsigned char *pdu,
                             unsigned int         len,
                             struct mms_message  *out);
gboolean mms_message_encode (struct mms_message *msg,
                             int                 fd);
void mms_message_free (struct mms_message *msg);
const char *mms_message_status_get_string (enum mms_message_status status);
char *mms_message_create_smil (GVariant *attachments);
const char *message_rsp_status_to_string (enum mms_message_rsp_status status);

#endif /* CHAN_MM_MMS_VENDOR_MMSUTIL_H */
