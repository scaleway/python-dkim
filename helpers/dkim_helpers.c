#include <dkim.h>
#include <stdio.h>
#include <string.h>

#include "dkim_helpers.h"

static DKIM_LIB *s_dkim_lib = NULL;

DKIM_STAT signer_init() {
  s_dkim_lib = dkim_init(NULL, NULL);
  if (s_dkim_lib == NULL) {
    return DKIM_STAT_INTERNAL;
  }

  return DKIM_STAT_OK;
}

DKIM_STAT signer_quit() {
  dkim_close(s_dkim_lib);
  s_dkim_lib = NULL;

  return DKIM_STAT_OK;
}

DKIM_STAT process_message(DKIM *_dkim_message_handle,
                          const signer_sign_pm *_info) {
  DKIM_STAT dkim_status;

  unsigned int i = 0;
  for (i = 0; i < _info->header_array_length; i++) {
    dkim_status =
        dkim_header(_dkim_message_handle, _info->header_array[i].header,
                    _info->header_array[i].size);
    if (dkim_status != DKIM_STAT_OK)
      return dkim_status;
  }

  dkim_status = dkim_eoh(_dkim_message_handle);
  if (dkim_status != DKIM_STAT_OK)
    return dkim_status;

  dkim_status = dkim_body(_dkim_message_handle, _info->body, _info->body_size);
  if (dkim_status == DKIM_STAT_INVALID)
    return dkim_status;

  dkim_status = dkim_eom(_dkim_message_handle, NULL);

  if (dkim_status != DKIM_STAT_OK)
    return dkim_status;

  return DKIM_STAT_OK;
}

DKIM_STAT signer_sign(const signer_sign_pm *_info) {
  DKIM_STAT dkim_status;
  const unsigned char JOB_ID[] = "signing";
  const unsigned int USED_LENGTH_DKIM_SIGNHEADER =
      strlen(DKIM_SIGNHEADER) +
      2; // Length used for the first part of the signature, that is
         // DKIM-Signature:<space char>
  memset(_info->out_signature_buffer, '0', _info->out_signature_buffer_size);

  DKIM *dkim_msg_handle = dkim_sign(
      s_dkim_lib, JOB_ID, NULL, (dkim_sigkey_t)_info->secret_key,
      _info->selector, _info->signing_domain, _info->dkim_header_canon,
      _info->dkim_body_canon, DKIM_SIGN_RSASHA256,
      -1, // Sign the whole body
      &dkim_status);

  if (dkim_msg_handle == NULL)
    return DKIM_STAT_INTERNAL;

  dkim_status = process_message(dkim_msg_handle, _info);
  if (dkim_status != DKIM_STAT_OK)
    return dkim_status;

  dkim_status = dkim_getsighdr(dkim_msg_handle, _info->out_signature_buffer,
                               _info->out_signature_buffer_size,
                               USED_LENGTH_DKIM_SIGNHEADER);

  if (dkim_status != DKIM_STAT_OK)
    return dkim_status;

  dkim_free(dkim_msg_handle);

  return DKIM_STAT_OK;
}

DKIM_STAT signer_verify(const signer_sign_pm *_info) {
  const unsigned char JOB_ID[] = "verifying";
  DKIM_STAT dkim_status;

  DKIM *dkim_msg_handle = dkim_verify(s_dkim_lib, JOB_ID, NULL, &dkim_status);

  dkim_status = process_message(dkim_msg_handle, _info);

  if (dkim_status != DKIM_STAT_OK)
    return dkim_status;

  dkim_free(dkim_msg_handle);

  return dkim_status;
}
