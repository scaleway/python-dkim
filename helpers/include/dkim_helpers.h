#ifndef SIGNER_H
#define SIGNER_H

/// Max header size specified by libopendkim, 4096+1 to include the terminating
/// null character
#define SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE 4097

/// Struct used to pass message headers to signer_sign
typedef struct signer_eml_header_t {
  unsigned char *header; /// header to be DKIM signed
  unsigned int size;     /// header's size in bytes
} signer_eml_header;

/// Parameter struct to signer_sign
typedef struct signer_sign_pm_t {
  const unsigned char *signing_domain; /// domain sending the email and
                                       /// therefore which must sign the email
  const unsigned char *selector;       /// domain's dkim selector
  signer_eml_header *header_array;     /// headers to be dkim-signed
  unsigned int header_array_length;    /// the length of the header array
  unsigned char *body;                 /// email's body
  unsigned int body_size;              /// email's body size in bytes
  const unsigned char *secret_key;     /// domain's rsa private key
  unsigned char
      *out_signature_buffer; /// output buffer receiving the DKIM signature

  /// Must be SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE bytes long, otherwise your
  /// signature might be truncated. signer_sign will return an error if your
  /// buffer is greater than SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE.
  unsigned int out_signature_buffer_size;

  int dkim_header_canon;
  int dkim_body_canon;

} signer_sign_pm;

/// Init the library. Returns DKIM_STAT_OK in case of success,
/// DKIM_STAT_INTERNAL otherwise
int signer_init(void);
int signer_quit(void);
int signer_sign(const signer_sign_pm *_info);
int signer_verify(const signer_sign_pm *_info);

typedef int SIGNER_STAT;

#define DKIM_STAT_OK 0             /* function completed successfully */
#define DKIM_STAT_BADSIG 1         /* signature available but failed */
#define DKIM_STAT_NOSIG 2          /* no signature available */
#define DKIM_STAT_NOKEY 3          /* public key not found */
#define DKIM_STAT_CANTVRFY 4       /* can't get domain key to verify */
#define DKIM_STAT_SYNTAX 5         /* message is not valid syntax */
#define DKIM_STAT_NORESOURCE 6     /* resource unavailable */
#define DKIM_STAT_INTERNAL 7       /* internal error */
#define DKIM_STAT_REVOKED 8        /* key found, but revoked */
#define DKIM_STAT_INVALID 9        /* invalid function parameter */
#define DKIM_STAT_NOTIMPLEMENT 10  /* function not implemented */
#define DKIM_STAT_KEYFAIL 11       /* key retrieval failed */
#define DKIM_STAT_CBREJECT 12      /* callback requested reject */
#define DKIM_STAT_CBINVALID 13     /* callback gave invalid result */
#define DKIM_STAT_CBTRYAGAIN 14    /* callback says try again later */
#define DKIM_STAT_CBERROR 15       /* callback error */
#define DKIM_STAT_MULTIDNSREPLY 16 /* multiple DNS replies */
#define DKIM_STAT_SIGGEN 17        /* signature generation failed */

#endif