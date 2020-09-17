open! Core
open! Async
open! Import
module Connection = Ssl.Connection


(** Accept TCP connections, do a TLS negotiation on each connection and call [f] with the
    encrypted channel.

    The connection is shutdown cleanly when [f] returns. *)
val listen
  :  ?max_connections:int
  -> ?backlog:int
  -> ?buffer_age_limit:Async.Writer.buffer_age_limit
  -> Config.Server.t
  -> ('socket, 'addr) Tcp.Where_to_listen.t
  -> on_handler_error:[ `Call of 'socket -> exn -> unit | `Ignore | `Raise ]
  -> f:('socket -> Connection.t -> Reader.t -> Writer.t -> unit Deferred.t)
  -> ('socket, 'addr) Tcp.Server.t Deferred.t

(** Wrap a provided reader/writer pair. [f] will be called with the application end
    Reader/Writer.

    Once [f] returns we flush and close the TLS connection and [wrap_serve_connection]
    returns.

    This is for use by protocols that do dynamic TLS upgrade (e.g. SMTP and XMPP) *)
val wrap_server_connection
  :  Config.Server.t
  -> Reader.t
  -> Writer.t
  -> f:(Connection.t -> Reader.t -> Writer.t -> 'res Deferred.t)
  -> 'res Deferred.t

(** Establish a TCP connection to a TLS server and call [f] with the encrypted channel.

    The connection is shutdown cleanly  when [f] returns. *)
val with_connection
  :  ?interrupt:unit Deferred.t
  -> Config.Client.t
  -> 'socket Tcp.Where_to_connect.t
  -> f:
       (([ `Active ], 'socket) Socket.t
        -> Connection.t
        -> Reader.t
        -> Writer.t
        -> 'res Deferred.t)
  -> 'res Deferred.t

(** Wrap a provided reader/writer pair. [f] will be called with the application end
    Reader/Writer. Once [f] returns we flush and close the TLS connection and
    [wrap_client_connection] returns.

    This is for use by protocols that do dynamic TLS upgrade (e.g. SMTP and XMPP) *)
val wrap_client_connection
  :  Config.Client.t
  -> Reader.t
  -> Writer.t
  -> f:(Connection.t -> Reader.t -> Writer.t -> 'res Deferred.t)
  -> 'res Deferred.t
