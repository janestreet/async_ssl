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
  -> ?socket:([ `Unconnected ], ([< Socket.Address.t ] as 'socket)) Socket.t
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

    The connection is shutdown cleanly when [f] returns. *)
val with_connection
  :  ?interrupt:unit Deferred.t
  -> ?timeout:Time_ns.Span.t
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
  :  ?timeout:Time_ns.Span.t
  -> Config.Client.t
  -> Reader.t
  -> Writer.t
  -> f:(Connection.t -> Reader.t -> Writer.t -> 'res Deferred.t)
  -> 'res Deferred.t

module Expert : sig
  (** Prefer calling [with_connection]. This is provided for completeness and backwards
      compatibility. You must handle closing the [Reader.t] and [Writer.t] returned by
      [connect] yourself. *)
  val connect
    :  ?interrupt:unit Deferred.t
    -> ?timeout:Time_ns.Span.t
    -> Config.Client.t
    -> 'socket Tcp.Where_to_connect.t
    -> (([ `Active ], 'socket) Socket.t * Connection.t * Reader.t * Writer.t) Deferred.t

  (** [wrap_client_connection] will immediately tear down the connection as soon as [f]
      returns. This doesn't accommodate cases where ['res] contains more [Async]
      primitives, such as a [Pipe.Reader.t]. [wrap_client_connection_and_stay_open] gives
      callers the agency to control when this teardown occurs.

      Callers must ensure that [`Do_not_close_until] becomes determined to avoid leaking
      file descriptors. The [unit Deferred.t] returned in [`Do_not_close_until] is also
      returned in [`Connection_closed] in case functions external to
      [wrap_client_connection_and_stay_open] care whether the TLS session has been torn
      down.

      It is an error to access the [Reader.t]/[Writer.t] once [`Do_not_close_until] has
      become determined (doing so may result in weird IO errors). *)
  val wrap_client_connection_and_stay_open
    :  Config.Client.t
    -> Reader.t
    -> Writer.t
    -> f:
         (Connection.t
          -> Reader.t
          -> Writer.t
          -> ('res * [ `Do_not_close_until of unit Deferred.t ]) Deferred.t)
    -> ('res * [ `Connection_closed of unit Deferred.t ]) Deferred.t
end

module For_testing : sig
  val listen
    :  ?max_connections:int
    -> ?backlog:int
    -> ?buffer_age_limit:Async.Writer.buffer_age_limit
    -> ?advance_clock_before_tls_negotiation:read_write Time_source.T1.t * Time_ns.Span.t
    -> ?socket:([ `Unconnected ], ([< Socket.Address.t ] as 'socket)) Socket.t
    -> Config.Server.t
    -> ('socket, 'addr) Tcp.Where_to_listen.t
    -> on_handler_error:[ `Call of 'socket -> exn -> unit | `Ignore | `Raise ]
    -> f:('socket -> Connection.t -> Reader.t -> Writer.t -> unit Deferred.t)
    -> ('socket, 'addr) Tcp.Server.t Deferred.t

  val with_connection
    :  ?interrupt:unit Deferred.t
    -> ?timeout:Time_ns.Span.t
    -> Config.Client.t
    -> 'socket Tcp.Where_to_connect.t
    -> f:
         (([ `Active ], 'socket) Socket.t
          -> Connection.t
          -> Reader.t
          -> Writer.t
          -> 'res Deferred.t)
    -> time_source:Time_source.t
    -> 'res Deferred.t
end
