-module(ssh_key_default).

-export([public_host_dsa_key/2, private_host_dsa_key/2,
         public_host_rsa_key/2, private_host_rsa_key/2,
         public_host_key/2, private_host_key/2,
         public_identity_key/2, private_identity_key/2,
         lookup_host_key/3, add_host_key/3, lookup_user_key/3]).

-define(PERM_700, 8#700).
-define(PERM_644, 8#644).

-include_lib("public_key/include/public_key.hrl"). 

-include("ssh.hrl").
%-include("PKCS-1.hrl").
%-include("DSS.hrl").

%%
%% API
%%
public_host_dsa_key(Type, Options) ->
    File = file_name(Type, "ssh_host_dsa_key.pub", Options),
    read_public_key_v2(File, "ssh-dss").

private_host_dsa_key(Type, Opts) ->
    File = file_name(Type, "ssh_host_dsa_key", Opts),
    read_private_key_v2(File, "ssh-dss").

public_host_rsa_key(Type, Opts) ->
    File = file_name(Type, "ssh_host_rsa_key.pub", Opts),
    read_public_key_v2(File, "ssh-rsa").

private_host_rsa_key(Type, Opts) ->
    File = file_name(Type, "ssh_host_rsa_key", Opts),
    read_private_key_v2(File, "ssh-rsa").

public_host_key(Type, Opts) ->
    File = file_name(Type, "ssh_host_key", Opts),
    case read_private_key_v1(File,public) of
	{error, enoent} ->	
	    read_public_key_v1(File++".pub");
	Result ->
	    Result
    end.

private_host_key(Type, Opts) ->
    File = file_name(Type, "ssh_host_key", Opts),
    read_private_key_v1(File,private).

public_identity_key(Alg, Opts) ->
    Path = file_name(user, identity_key_filename(Alg) ++ ".pub", Opts),
    read_public_key_v2(Path, Alg).

private_identity_key(Alg, Opts) ->
    Path = file_name(user, identity_key_filename(Alg), Opts),
    read_private_key_v2(Path, Alg).

lookup_host_key(Host, Alg, Opts) ->
    Host1 = replace_localhost(Host),
    do_lookup_host_key(Host1, Alg, Opts).

add_host_key(Host, Key, Opts) ->
    Host1 = add_ip(replace_localhost(Host)),
    KnownHosts = file_name(user, "known_hosts", Opts),
    case file:open(KnownHosts, [write,append]) of
   	{ok, Fd} ->
	    ok = file:change_mode(KnownHosts, ?PERM_644),
   	    Res = add_key_fd(Fd, Host1, Key),
   	    file:close(Fd),
   	    Res;
   	Error ->
   	    Error
    end.

lookup_user_key(User, Alg, Opts) ->
    SshDir = ssh_dir({remoteuser,User}, Opts),
    case lookup_user_key_f(User, SshDir, Alg, "authorized_keys", Opts) of
        {ok, Key} ->
            {ok, Key};
        _ ->
            lookup_user_key_f(User, SshDir, Alg,  "authorized_keys2", Opts)
    end.

%%
%% Internal functions
%%
%% in: "host" out: "host,1.2.3.4.
lookup_user_key_f(_User, [], _Alg, _F, _Opts) ->
    {error, nouserdir};
lookup_user_key_f(_User, nouserdir, _Alg, _F, _Opts) ->
    {error, nouserdir};
lookup_user_key_f(_User, Dir, Alg, F, _Opts) ->
    FileName = filename:join(Dir, F),
    case file:open(FileName, [read]) of
	{ok, Fd} ->
	    Res = lookup_user_key_fd(Fd, Alg),
	    file:close(Fd),
	    Res;
	{error, Reason} ->
	    {error, {{openerr, Reason}, {file, FileName}}}
    end.

lookup_user_key_fd(Fd, Alg) ->
    case io:get_line(Fd, '') of
	eof ->
	    {error, not_found};
	Line ->
	    case string:tokens(Line, " ") of
		[Alg, KeyData, _] ->
		    %% 		    io:format("lookup_user_key_fd: HostList ~p Alg ~p KeyData ~p\n",
		    %% 			      [HostList, Alg, KeyData]),
		    decode_public_key_v2(base64:mime_decode(KeyData), Alg);
		_Other ->
		    %%?dbg(false, "key_fd Other: ~w ~w\n", [Alg, _Other]),
		    lookup_user_key_fd(Fd, Alg)
	    end
    end.

add_ip(Host) ->
    case inet:getaddr(Host, inet) of
	{ok, Addr} ->
	    case ssh_connection:encode_ip(Addr) of
		false -> 
                    Host;
		IPString -> 
                    Host ++ "," ++ IPString
	    end;
	_ -> Host
    end.    

add_key_fd(Fd, Host, #ssh_key{type = rsa, public = {N,E}}) ->
    DK = base64:encode(ssh_bits:encode(["ssh-rsa",E,N],
                                             [string,mpint,mpint])),
    file:write(Fd, [Host, " ssh-rsa ", DK, "\n"]);

add_key_fd(Fd, Host, #ssh_key{type = dsa, public = {P,Q,G,Y}}) ->
    DK = base64:encode(ssh_bits:encode(["ssh-dss",P,Q,G,Y],
                                             [string,mpint,mpint,mpint,mpint])),
    file:write(Fd, [Host, " ssh-dss ", DK, "\n"]).

do_lookup_host_key(Host, Alg, Opts) ->
    case file:open(file_name(user, "known_hosts", Opts), [read]) of
	{ok, Fd} ->
	    Res = lookup_host_key_fd(Fd, Host, Alg),
	    file:close(Fd),
	    Res;
	{error, enoent} -> {error, not_found};
	Error -> Error
    end.

lookup_host_key_fd(Fd, Host, Alg) ->
    case io:get_line(Fd, '') of
	eof ->
	    {error, not_found};
	Line ->
	    case string:tokens(Line, " ") of
		[HostList, Alg, KeyData] ->
		    case lists:member(Host, string:tokens(HostList, ",")) of
			true ->
			    decode_public_key_v2(base64:mime_decode(KeyData), Alg);
			false ->
			    lookup_host_key_fd(Fd, Host, Alg)
		    end;
		_ ->
		    lookup_host_key_fd(Fd, Host, Alg)
	    end
    end.

replace_localhost("localhost") ->
    {ok, Hostname} = inet:gethostname(),
    Hostname;
replace_localhost(Host) ->
    Host.

identity_key_filename("ssh-dss") -> "id_dsa";
identity_key_filename("ssh-rsa") -> "id_rsa".

read_public_key_v1(File) ->
    case file:read_file(File) of
	{ok,Bin} ->
	    List = binary_to_list(Bin),
	    case io_lib:fread("~d ~d ~d ~s", List) of
		{ok,[_Sz,E,N,Comment],_} ->
		    {ok,#ssh_key { type = rsa,
				   public ={N,E},
				   comment = Comment }};
		_Error ->
		    {error, bad_format}
	    end;
	Error ->
	    Error
    end.

read_private_key_v1(File, Type) ->
    case file:read_file(File) of
	{ok,<<"SSH PRIVATE KEY FILE FORMAT 1.1\n",0,
	     CipherNum,_Resereved:32,Bin/binary>>} ->
	    decode_private_key_v1(Bin, CipherNum,Type);
	{ok,_} ->
	    {error, bad_format};
	Error ->
	    Error
    end.

decrypt1(Bin, CipherNum) ->
    decrypt1(Bin, CipherNum,"").

decrypt1(Bin, CipherNum, Phrase) ->
    if CipherNum == ?SSH_CIPHER_NONE; Phrase == "" ->
	    Bin;
       CipherNum == ?SSH_CIPHER_3DES ->
	    <<K1:8/binary, K2:8/binary>> = erlang:md5(Phrase),
	    K3 = K1,
	    IV = <<0,0,0,0,0,0,0,0>>,
	    Bin1 = crypto:des_cbc_decrypt(K3,IV,Bin),
	    Bin2 = crypto:des_cbc_encrypt(K2,IV,Bin1),
	    crypto:des_cbc_decrypt(K1,IV,Bin2)
    end.

decode_private_key_v1(Bin, CipherNum, Type) ->
    case ssh_bits:decode(Bin,0,[uint32, bignum, bignum, string]) of
	{Offset,[_NSz,N,E,Comment]} ->
	    if Type == public ->
		    {ok,#ssh_key { type=rsa,
				   public={N,E},
				   comment=Comment}};
	       Type == private ->
		    <<_:Offset/binary, Encrypted/binary>> = Bin,
		    case ssh_bits:decode(decrypt1(Encrypted, CipherNum),0,
					 [uint32, bignum, bignum, 
					  bignum, bignum,{pad,8}]) of
			{_,[_,D,IQMP,Q,P]} ->
			    {ok,#ssh_key { type=rsa,
					   public={N,E},
					   private={D,IQMP,Q,P},
					   comment=Comment}};
			_ ->
			    {error,bad_format}
		    end
	    end;
	_ ->
	    {error,bad_format}
    end.

read_private_key_v2(File, Type) ->
    case file:read_file(File) of
        {ok, PemBin} ->
            case catch (public_key:pem_decode(PemBin)) of
                [{_, Bin, not_encrypted}] ->
                    decode_private_key_v2(Bin, Type);
                Error -> %% Note we do not handle password encrypted keys at the moment
                    {error, Error}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

decode_private_key_v2(Private,"ssh-rsa") ->
    case 'PKCS-1':decode( 'RSAPrivateKey', Private) of
	{ok,RSA} -> %% FIXME Check for two-prime version
	    {ok, #ssh_key { type = rsa,
			    public = {RSA#'RSAPrivateKey'.modulus,
				      RSA#'RSAPrivateKey'.publicExponent},
			    private = {RSA#'RSAPrivateKey'.modulus,
				       RSA#'RSAPrivateKey'.privateExponent}
			    }};
	Error ->
	    Error
    end;
decode_private_key_v2(Private, "ssh-dss") ->
    case 'DSS':decode('DSAPrivateKey', Private) of
	{ok,DSA} -> %% FIXME Check for two-prime version
	    {ok, #ssh_key { type = dsa,
			    public = {DSA#'DSAPrivateKey'.p,
				      DSA#'DSAPrivateKey'.q,
				      DSA#'DSAPrivateKey'.g,
				      DSA#'DSAPrivateKey'.y},
			    private= {DSA#'DSAPrivateKey'.p,
				      DSA#'DSAPrivateKey'.q,
				      DSA#'DSAPrivateKey'.g,
				      DSA#'DSAPrivateKey'.x}
			   }};
	_ ->
	    {error,bad_format}
    end.

file_name(Type, Name, Opts) ->
    filename:join(ssh_dir(Type, Opts), Name).

ssh_dir({remoteuser, User}, Opts) ->
    case proplists:get_value(user_dir_fun, Opts) of
	undefined ->
	    case proplists:get_value(user_dir, Opts) of
		undefined ->
		    default_user_dir();
		Dir ->
		    Dir
	    end;
	FUN ->
	    FUN(User)
    end;

%% client use this to find client ssh keys
ssh_dir(user, Opts) ->
    case proplists:get_value(user_dir, Opts, false) of
	false -> default_user_dir();
	D -> D
    end;

%% server use this to find server host keys
ssh_dir(system, Opts) ->
    proplists:get_value(system_dir, Opts, "/etc/ssh").

default_user_dir()->
    {ok,[[Home|_]]} = init:get_argument(home),
    UserDir = filename:join(Home, ".ssh"),
    ok = filelib:ensure_dir(filename:join(UserDir, "dummy")),
    ok = file:change_mode(UserDir, ?PERM_700),
    UserDir.

read_public_key_v2(File, Type) ->
    case file:read_file(File) of
	{ok,Bin} ->
            parse_bin(Type, catch public_key:ssh_decode(Bin, public_key));
        Error ->
	    Error
    end.

parse_bin(_, {'EXIT', _Reason}) ->
    {error, bad_format};
parse_bin("ssh-rsa", [{#'RSAPublicKey'{modulus = _M, publicExponent = _PE} = RSA}]) ->
    RSA;
%% For details on p, q, g, see 
%% http://www.erlang.org/doc/apps/public_key/public_key_records.html
parse_bin("ssh-dsa", [{{_Int, #'Dss-Parms'{p = _P, q = _Q, g = _G}} = DSS}]) ->
    DSS.

decode_public_key_v2(K_S, "ssh-rsa") ->
    case ssh_bits:decode(K_S,[string,mpint,mpint]) of
	["ssh-rsa", E, N] ->
	    {ok, #ssh_key { type = rsa,
			    public = {N,E},
			    comment=""}};
	_ ->
	    {error, bad_format}
    end;
decode_public_key_v2(K_S, "ssh-dss") ->
    case ssh_bits:decode(K_S,[string,mpint,mpint,mpint,mpint]) of
	["ssh-dss",P,Q,G,Y] ->
	    {ok,#ssh_key { type = dsa,
			   public = {P,Q,G,Y}
			  }};
	_A ->
	    {error, bad_format}
    end;
decode_public_key_v2(_, _) ->
    {error, bad_format}.
