cdef extern from 'dkim_helpers.h':
    cdef struct signer_eml_header_t:
        unsigned char* header
        unsigned int size

    ctypedef signer_eml_header_t signer_eml_header
    
    cdef struct signer_sign_pm_t:
        const unsigned char* signing_domain;
        const unsigned char* selector;
        signer_eml_header* header_array;
        unsigned int header_array_length;
        unsigned char* body;
        unsigned int body_size;
        const unsigned char* secret_key;
        unsigned char* out_signature_buffer;
        unsigned int out_signature_buffer_size;
        int dkim_header_canon;
        int dkim_body_canon;

    ctypedef signer_sign_pm_t signer_sign_pm

    cdef const int SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE = 4097

    const int	DKIM_STAT_OK = 0
    const int	DKIM_STAT_BADSIG = 1
    const int	DKIM_STAT_NOSIG = 2
    const int	DKIM_STAT_NOKEY = 3
    const int	DKIM_STAT_CANTVRFY = 4
    const int	DKIM_STAT_SYNTAX = 	5
    const int	DKIM_STAT_NORESOURCE = 6
    const int	DKIM_STAT_INTERNAL = 7
    const int	DKIM_STAT_REVOKED = 8
    const int	DKIM_STAT_INVALID = 9
    const int	DKIM_STAT_NOTIMPLEMENT = 10
    const int	DKIM_STAT_KEYFAIL = 11
    const int	DKIM_STAT_CBREJECT = 12
    const int	DKIM_STAT_CBINVALID = 13
    const int	DKIM_STAT_CBTRYAGAIN = 14
    const int	DKIM_STAT_CBERROR = 15
    const int	DKIM_STAT_MULTIDNSREPLY = 16
    const int	DKIM_STAT_SIGGEN = 17

    int signer_sign(const signer_sign_pm* _info)
    int signer_verify(const signer_sign_pm* _info)
    int signer_init()
    int signer_quit()
