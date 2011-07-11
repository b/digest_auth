%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc digest_auth startup code

-module(digest_auth).
-author('author <author@example.com>').
-export([start/0, start_link/0, stop/0]).
-export([is_authorized/3]).
-export([challenge/1, is_valid/1]).
-export([get_password/2]).

ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok
    end.

%% @spec start_link() -> {ok,Pid::pid()}
%% @doc Starts the app for inclusion in a supervisor tree
start_link() ->
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    digest_auth_sup:start_link().

%% @spec start() -> ok
%% @doc Start the digest_auth server.
start() ->
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    application:start(digest_auth).

%% @spec stop() -> ok
%% @doc Stop the digest_auth server.
stop() ->
    Res = application:stop(digest_auth),
    application:stop(webmachine),
    application:stop(mochiweb),
    application:stop(crypto),
    application:stop(inets),
    Res.

is_authorized(ReqData, Realm, PasswordFun) ->
	case wrq:get_req_header("Authorization", ReqData) of
		undefined -> challenge(Realm);
		AuthData ->
			case AuthData of
				"Digest " ++ _Params ->
					BaseParams = parse_params(_Params),
					Username = proplists:get_value(username, BaseParams),
					Password = PasswordFun(Realm, Username),
					Method = erlang:atom_to_list(wrq:method(ReqData)),
					Uri = proplists:get_value(uri, BaseParams),
					Body = case wrq:req_body(ReqData) of
						undefined -> "";
						<<>> -> "";
						B -> B
					end,
					Params = lists:ukeysort(1, lists:append([{password, Password}, {method, Method}, {uri, Uri}, {body, Body}], BaseParams)),
					Response = nonce_cache:validate(Params),
					is_authorized_response(Response, Realm);
				_ -> challenge(Realm)
			end
	end.
	
is_authorized_response(ok, _Realm) -> true;
is_authorized_response({_Code, _Result}, Realm) -> challenge(Realm).

hexify(String) when erlang:is_list(String) ->
	hexify(erlang:list_to_binary(String));
hexify(Binary) when erlang:is_binary(Binary) ->
	string:to_lower(lists:flatten([[erlang:integer_to_list(N1, 16), erlang:integer_to_list(N2, 16)]
	                                  || << N1:4, N2:4 >> <= Binary])).
make_random_string() ->
	Seed = crypto:rand_bytes(32),
	Hash = crypto:sha(Seed),
	hexify(Hash).

challenge(Realm) ->
	Nonce = make_random_string(), Opaque = make_random_string(),
	ok = nonce_cache:insert(Nonce, Opaque),
	make_challenge(Realm, Nonce, Opaque).

make_challenge(Realm, Nonce, Opaque) ->
		"Digest realm=\"" ++ Realm ++
		"\",qop=\"auth,auth-int\"" ++
		",nonce=\"" ++ Nonce ++
		"\",opaque=\"" ++ Opaque ++ "\"".

get_password(_Realm, Username) ->
	proplists:get_value(Username, [
		{"foo", "bar"}, {"baz", "bal"}
	]).

parse_params(Params) ->
	[ parse_param_pair(string:tokens(P, "=")) || P <- string:tokens(Params, ", ") ].

parse_param_pair([Key, Value]) ->
	{erlang:list_to_atom(Key), strip_quotes(Value)}.

strip_quotes(String) -> string:strip(String, both, $").

is_valid(Params) ->
	Response = proplists:get_value(response, Params),
	Response == make_response(proplists:get_value(qop, Params), Params).

make_response(undefined, Params) ->
	HA1 = ha1(Params),
	Nonce = proplists:get_value(nonce, Params),
	HA2 = ha2(undefined, Params),
	hexify(crypto:md5(HA1 ++ ":" ++ Nonce ++ ":" ++ HA2));
make_response(Qop, Params) ->
	HA1 = ha1(Params),
	Nonce = proplists:get_value(nonce, Params),
	NC = proplists:get_value(nc, Params),
	CNonce = proplists:get_value(cnonce, Params),
	HA2 = ha2(Qop, Params),
	hexify(crypto:md5(HA1 ++ ":" ++ Nonce ++ ":" ++ NC ++
	                  ":" ++ CNonce ++ ":" ++ Qop ++ ":" ++ HA2)).

ha1(Params) ->
	Password = proplists:get_value(password, Params),
	ha1_pw(Password, Params).

ha1_pw(undefined, _Params) -> [];
ha1_pw(Password, Params) ->
	Username = proplists:get_value(username, Params),
	Realm = proplists:get_value(realm, Params),
	hexify(crypto:md5(Username ++ ":" ++ Realm ++ ":" ++ Password)).

ha2(undefined, Params) -> ha2_rfc2069(Params);
ha2("auth", Params) -> ha2_rfc2069(Params);
ha2("auth-int", Params) -> 
	Method = proplists:get_value(method, Params),
	URI = proplists:get_value(uri, Params),
	Body = proplists:get_value(body, Params),
	hexify(crypto:md5(Method ++ ":" ++ URI ++ ":" ++ hexify(crypto:md5(Body)))).

ha2_rfc2069(Params) ->
	Method = proplists:get_value(method, Params),
	URI = proplists:get_value(uri, Params),
	hexify(crypto:md5(Method ++ ":" ++ URI)).
