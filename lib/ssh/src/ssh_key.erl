%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2011-2012. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%%
%% %CopyrightEnd%
%%

-module(ssh_key).

-include("ssh.hrl").
-include("PKCS-1.hrl").
-include("DSS.hrl").

-export([public_host_dsa_key/2,private_host_dsa_key/2,
	 public_host_rsa_key/2,private_host_rsa_key/2,
	 public_host_key/2,private_host_key/2,
         public_identity_key/2, private_identity_key/2, 
	 lookup_host_key/3, add_host_key/3, lookup_user_key/3]).

%%%
%%% API
%%% 
public_host_dsa_key(Type, Options) ->
    callback(public_host_dsa_key, Options, [Type, Options]).

private_host_dsa_key(Type, Options) ->
    callback(private_host_dsa_key, Options, [Type, Options]).

public_host_rsa_key(Type, Options) ->
    callback(public_host_rsa_key, Options, [Type, Options]).

private_host_rsa_key(Type, Options) ->
    callback(private_host_rsa_key, Options, [Type, Options]).

public_host_key(Type, Options) ->
    callback(public_host_key, Options, [Type, Options]).

private_host_key(Type, Options) ->
    callback(private_host_key, Options, [Type, Options]).

public_identity_key(Algorithm, Options) ->
    callback(public_identity_key, Options, [Algorithm, Options]).

private_identity_key(Algorithm, Options) ->
    callback(private_identity_key, Options, [Algorithm, Options]).

lookup_host_key(Host, Algorithm, Options) ->
    callback(lookup_host_key, Options, [Host, Algorithm, Options]).

add_host_key(Host, Key, Options) ->
    callback(add_host_key, Options, [Host, Key, Options]).
    
lookup_user_key(User, Algorithm, Options) ->
    callback(lookup_user_key, Options, [User, Algorithm, Options]).

%%%
%%% Internal functions
%%%
callback(Fun, Options, Args) ->
    case proplists:get_value(user_key_callback, Options) of
        Mod when Mod =/= undefined ->
            case lists:member({Fun, length(Args)}, Mod:module_info(exports)) of
                true ->
                    erlang:apply(Mod, Fun, Args);
                _ ->
                    erlang:apply(ssh_key_default, Fun, Args)
            end;
        _ ->
            erlang:apply(ssh_key_default, Fun, Args)
    end.
