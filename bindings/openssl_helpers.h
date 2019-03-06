char **async_ssl__subject_alt_names(const X509 *cert);
void async_ssl__free_subject_alt_names(char **results);
char *async_ssl__pem_peer_certificate_chain(const SSL *con);
void async_ssl__free_pem_peer_certificate_chain(char *certs);
