## Release v0.17.0
- Fix known compatibility issues with OpenSSL 3.x (particularly on Mac OS X and some
  Linux distributions)
- Added basic support for using ALPN on the client and server side for protocol selection.
  You can specify which protocols your support when initializing the client/server using the [?alpn_protocols]
  argument, and then determine which protocol was negotiated using [Tls.Connection.alpn_selected].
- Improved hostname + certificate verification logic.
  We now use the openssl 1.1+ verification functionality directly instead of relying on
  our own (much slower) logic using ocaml_x509.

## Release v0.16.0

- Removed Support for OpenSSL 1.0. We now require OpenSSL 1.1.x.
  (OpenSSL 3.x should also work but is untested).
- Added new configuration option `override_security_level` as an escape hatch to
  override the system wide OpenSSL security level.
  See `Ssl.Override_security_level`
- Added `Connection.peer_certificate_fingerprint` and `Certificate.fingerprint`.
- Expose `?socket` on `Tls.listen` to allow configuring the underlying listening socket.
  See `Async_unix.Tcp.Server.create`.

## Old pre-v0.15 changelogs (very likely stale and incomplete)

## git version

- Added function `Ffi.set_default_verify_paths`, to make OpenSSL use its default for
  CA certificates locations

## 113.33.00

- Make sure to close the `Pipe.Writer.t` that goes back to the application, otherwise the
  application will never get an `Eof if the connection is closed.

## 113.24.00

- Switched to ppx.

## 113.00.00

- Added `Ssl.Connection.close`.

## 112.35.00

- Fix github issue #4 (some comments swapped).

## 112.24.00

- By default OpenSSL ignores the result of certificate validation, so we need to
  tell it not to.

- Expose session details such as checked certificates and negotiated version.
  Add session resumption.

## 112.17.00

- moved ffi_bindings and ffi_stubgen in separate libraries

## 111.21.00

- Upgraded to use new ctypes and its new stub generation methods.

## 111.08.00

- Improved the propagation of SSL errors to the caller.

## 111.06.00

Initial release
