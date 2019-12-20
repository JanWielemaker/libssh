/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2019, VU University Amsterdam
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

:- module(ssh_server,
          [ ssh_server/0,
            ssh_server/1                        % +Options
          ]).
:- use_module(library(debug)).
:- use_module(library(option)).
:- use_module(library(settings)).

:- use_foreign_library(foreign(sshd4pl)).

/** <module> Embedded SSH server

This module defines an embedded SSH  server   for  SWI-Prolog  on top of
[libssh](https://libssh.org). This module allows for   a  safe secondary
access point to a running  Prolog  process.   A  typical  use case is to
provide a safe channal  or  inspection   and  maintenance  of servers or
embedded Prolog instances.

If possible, a _login_ to the Prolog process uses a _pseudo terminal_ to
realise normal terminal  interaction,  including   processing  of  ^C to
interrupt running queries. If  `libedit`  (editline)   is  used  as  the
command  line  editor  this  is  installed  (see  el_wrap/0),  providing
advanced command line editing and history.

The library currently support _login_  to   the  Prolog  process. Future
versions may also use the client access   and  exploit the SSH subsystem
interface to achieve safe interaction between Prolog peers.

@tbd Currently only supports Unix. A Windows port is probably doable. It
mostly requires finding a  sensible  replacement   for  the  Unix pseudo
terminal.

@tbd Implement running other commands than the Prolog toplevel.
*/

:- multifile
    verify_password/3.                  % +ServerName, +User, +Password

:- predicate_options(
       ssh_server/1, 1,
       [ name(atom),
         port(integer),
         bind_address(atom),
         host_key_file(atom),
         authorized_keys_file(atom),
         auth_methods(list(oneof([password,public_key])))
       ]).

:- setting(ssh_server_port, positive_integer, 2020,
           "Default port for SWI-Prolog SSH server").

%!  ssh_server is det.
%!  ssh_server(+PortOrOptions) is det.
%
%   Create an embedded SSH server in the  current Prolog process. If the
%   argument    is    an    integer     it      is     interpreted    as
%   ssh_server([port(Integer)]). Options:
%
%     - name(+Atom)
%       Name the server.  Passed as first argument to verify_password/3
%       to identify multiple servers.
%     - port(+Integer)
%       Port to listen on.  Default is 2020.
%     - bind_address(+Name)
%       Interface to listen to.  Default is `localhost`.  Use `*`
%       to grant acccess from all network interfaces.
%     - host_key_file(+File)
%
%       File name for the host private key. If omitted it searches for
%       `etc/ssh` below the current directory and user_app_config('etc/ssh')
%       (normally ``~/.config/swi-prolog/etc/ssh``). On failure it
%       creates, a directory `etc/ssh` with default host keys and uses
%       these.
%     - auth_methods(+ListOfMethod)
%       Set allowed authentication methods.  ListOfMethod is a list of
%       - password
%         Allow password login (see verify_password/3)
%       - public_key
%         Allow key based login (see `authorized_keys_file` below)
%       The default is derived from the `authorized_keys_file` option
%       and whether or not verify_password/3 is defined.
%     - authorized_keys_file(+File)
%       File name for a file holding the public keys for users that
%       are allows to login.  Activates auth_methods([public_key]).
%       This file is in OpenSSH format and contains a certificate
%       per line in the format
%
%         <type> <base64-key> <comment>
%
%       The the file `~/.ssh/authorized_keys` is present, this will
%       be used as default, granting anyone with access to this account
%       to access the server with the same keys. If the option is
%       present with value `[]` (empty list), no key file is used.


ssh_server :-
    ssh_server([]).

ssh_server(Port) :-
    integer(Port),
    !,
    ssh_server([port(Port)]).
ssh_server(Options) :-
    setting(ssh_server_port, DefPort),
    merge_options(Options,
                  [ port(DefPort),
                    bind_address(localhost)
                  ], Options1),
    (   option(name(Name), Options)
    ->  Alias = Name
    ;   option(port(Port), Options1),
        format(atom(Alias), 'sshd@~w', [Port])
    ),
    ensure_host_keys(Options1, Options2),
    add_authorized_keys(Options2, Options3),
    add_auth_methods(Options3, Options4),
    thread_create(ssh_server_nt(Options4), _,
                  [ alias(Alias),
                    detached(true)
                  ]).

ensure_host_keys(Options, Options) :-
    option(host_key_file(KeyFile), Options),
    !,
    (   access_file(KeyFile, read)
    ->  true
    ;   permission_error(read, ssh_host_key_file, KeyFile)
    ).
ensure_host_keys(Options0, Options) :-
    exists_file('etc/ssh/ssh_host_ecdsa_key'),
    !,
    Options = [host_key_file('etc/ssh/ssh_host_ecdsa_key')|Options0].
ensure_host_keys(Options0, Options) :-
    absolute_file_name(user_app_config('etc/ssh'), Dir,
                       [ file_type(directory),
                         access(exist),
                         file_errors(fail)
                       ]),
    !,
    Options = [host_key_file(Dir)|Options0].
ensure_host_keys(Options,
                 [ host_key_file('etc/ssh/ssh_host_ecdsa_key')
                 | Options
                 ]) :-
    print_message(informational, ssh_server(create_host_keys('etc/ssh'))),
    make_directory_path('etc/ssh'),
    shell('ssh-keygen -A -f .').

add_auth_methods(Options, Options) :-
    option(auth_methods(_), Options),
    !.
add_auth_methods(Options, [auth_methods(Methods)|Options]) :-
    findall(Method, option_auth_method(Options, Method), Methods).

option_auth_method(Options, public_key) :-
    option(authorized_keys_file(_), Options).
option_auth_method(_Options, password) :-
    predicate_property(verify_password(_,_,_), number_of_clauses(N)),
    N > 0.

add_authorized_keys(Options0, Options) :-
    option(authorized_keys_file(AuthKeysFile), Options0),
    !,
    (   AuthKeysFile == []
    ->  select_option(authorized_keys_file(AuthKeysFile), Options0, Options)
    ;   Options = Options0
    ).
add_authorized_keys(Options, [authorized_keys_file(AuthKeysFile)|Options]) :-
    expand_file_name('~/.ssh/authorized_keys', [AuthKeysFile]),
    access_file(AuthKeysFile, read),
    !.
add_authorized_keys(Options, Options).

%!  run_client(+In, +Out, +Err, +Command) is det.
%
%   Run Command using I/O from  the   triple  <In,  Out, Err>. Currently
%   Command is ignored and we always run the Prolog toplevel loop.

:- public run_client/4.

run_client(In, Out, Err, Command) :-
    setup_console(In, Out, Err),
    debug(ssh(server), 'Got SSH command ~q~n', [Command]),
    version,
    call_cleanup(prolog,
                 disable_line_editing(In, Out, Err)).

setup_console(In, Out, Err) :-
    set_stream(In,  alias(user_input)),
    set_stream(Out, alias(user_output)),
    set_stream(Err, alias(user_error)),
    set_stream(In,  alias(current_input)),
    set_stream(Out, alias(current_output)),
    enable_line_editing(In,Out,Err),
    true.

%!  enable_line_editing(+In, +Out, +Err) is det.
%
%   Enable line editing for the console.  This   is  by built-in for the
%   Windows console. We can also provide it   for the X11 xterm(1) based
%   console if we use the BSD libedit based command line editor.

:- if(exists_source(library(editline))).
:- use_module(library(editline)).
enable_line_editing(_In, _Out, _Err) :-
    current_prolog_flag(readline, editline),
    !,
    debug(ssh(server), 'Setting up line editing', []),
    el_wrap.
:- endif.
enable_line_editing(_In, _Out, _Err).

:- if(current_predicate(el_unwrap/1)).
disable_line_editing(_In, _Out, _Err) :-
    el_unwrap(user_input).
:- endif.
disable_line_editing(_In, _Out, _Err).

%!  verify_password(+ServerName, +User:atom, +Passwd:string) is semidet.
%
%   Hook that can  be  used  to   accept  password  based  logins.  This
%   predicate must succeeds to accept the User/Passwd combination.
%
%   @arg ServerName is the name provided with the name(Name) option when
%   creating the server or the empty list.


		 /*******************************
		 *           MESSAGES		*
		 *******************************/

:- multifile
    prolog:message//1.

prolog:message(ssh_server(create_host_keys(Dir))) -->
    [ 'SSH Server: Creating host keys in "~w"'-[Dir] ].
