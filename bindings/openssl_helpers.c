#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include "openssl_helpers.h"

/* Return a NULL-terminated array of strings representing the subjectAltNames in [cert].
 * If the subjectAltNames extension is not present, an array of length 0 is returned.
 *
 * NULL is returned if OpenSSL returns an unexpected value or if memory allocation fails.
 */
char **async_ssl__subject_alt_names(const X509 *cert) {
    unsigned int idx = 0, allocated = 0;
    STACK_OF(GENERAL_NAME) *gens = NULL;
    char **names = NULL, **names_old = NULL;
    int i = 0, crit = 0;

    allocated = 10;
    if ((names = malloc(allocated * sizeof(char *))) == NULL) {
        return NULL;
    }

    /* Grab the subjectAltName extension data and treat a [crit] of 1 and 0 identically.
     * We don't care about critical vs. non-critical extensions, since this is a
     * requirement put on CAs at certificate generation time.  It would only matter to us
     * if OpenSSL didn't understand subjectAltNames, in which case we should reject if we
     * don't understand a critical extension.
     *
     * RFC 5280 states that "a certificate MUST NOT include more than one instance of a
     * particular extension." (https://tools.ietf.org/html/rfc5280#section-4.2)
     */
    gens = X509_get_ext_d2i((X509 *)cert, NID_subject_alt_name, &crit, NULL);
    switch (crit) {
    case 1:    /* found, critical      */
    case 0:    /* found, non-critical  */
        break;
    case -1:   /* not found            */
        /* Return an empty list */
        names[0] = NULL;
        return names;
    case -2:   /* found multiple times */
    default:
        free(names);
        return NULL;
    }

    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        GENERAL_NAME *gen = NULL;
        unsigned char *cstr = NULL;
        unsigned int cstr_len = 0;

        gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type != GEN_DNS) {
            continue;
        }

        /* Keep an extra space for a NULL terminator */
        if (idx + 2 > allocated) {
            allocated *= 2;
            names_old = names;
            if ((names = realloc(names, allocated * sizeof(char *))) == NULL) {
                async_ssl__free_subject_alt_names(names_old);
                return NULL;
            }
        }

        cstr = ASN1_STRING_data(gen->d.dNSName);
        cstr_len = ASN1_STRING_length(gen->d.dNSName);
        if ((names[idx] = malloc((cstr_len + 1) * sizeof(char))) == NULL) {
            async_ssl__free_subject_alt_names(names);
            return NULL;
        }
        strncpy(names[idx], (char *)cstr, cstr_len);
        names[idx][cstr_len] = '\0';

        idx++;
    }

    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

    names[idx] = NULL;
    return names;
}

/* Free memory associated with results returned from an earlier call to
 * [async_ssl__subject_alt_names]. */
void async_ssl__free_subject_alt_names(char **results) {
    unsigned int i = 0;
    char *cur = NULL;

    while ((cur = results[i]) != NULL) {
        free(cur);
        i++;
    }
    free(results);

    return;
}

/* Return a PEM-formatted buffer containing the peer's certificate chain.
 *
 * NULL is returned if there is no certificate chain, or if memory allocation fails.
 */
char *async_ssl__pem_peer_certificate_chain(const SSL *con) {
    STACK_OF(X509) *cert_stack = NULL;
    BIO *bio = NULL;
    char *certs = NULL;
    int i = 0, pending_bytes = 0;

    /* [cert_stack] is not to be freed; [SSL_get_peer_cert_chain] simply returns an
     * internal pointer and no reference count is incremented. */
    if ((cert_stack = SSL_get_peer_cert_chain(con)) == NULL) {
        return NULL;
    }

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return NULL;
    }
    for (i = 0; i < sk_X509_num(cert_stack); i++) {
        if ((PEM_write_bio_X509(bio, sk_X509_value(cert_stack, i))) == 0) {
            goto cleanup;
        }
    }
    pending_bytes = BIO_ctrl_pending(bio);
    if ((certs = malloc((pending_bytes + 1) * sizeof(char))) == NULL) {
        goto cleanup;
    }
    if ((BIO_read(bio, certs, pending_bytes)) < pending_bytes) {
        free(certs);
        certs = NULL;
        goto cleanup;
    }
    certs[pending_bytes] = '\0';

  cleanup:
    BIO_set_close(bio, BIO_CLOSE);
    BIO_free(bio);

    return certs;
}

/* Free memory allocated for results returned from an earlier call to
 * [async_ssl__get_peer_cert_chain]. */
void async_ssl__free_pem_peer_certificate_chain(char *certs) {
    free(certs);
    return;
}
