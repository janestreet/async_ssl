char **async_ssl__subject_alt_names(const X509 *cert);
void async_ssl__free_subject_alt_names(char **results);
char *async_ssl__pem_peer_certificate_chain(const SSL *con);
void async_ssl__free_pem_peer_certificate_chain(char *certs);
void* async_ssl__set_alpn_callback (SSL_CTX* ctx, char* protocols, size_t len);
void async_ssl__free_alpn_callback (void* alpn_ctx);
