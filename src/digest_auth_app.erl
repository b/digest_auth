%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Callbacks for the digest_auth application.

-module(digest_auth_app).
-author('author <author@example.com>').

-behaviour(application).
-export([start/2,stop/1]).


%% @spec start(_Type, _StartArgs) -> ServerRet
%% @doc application start callback for digest_auth.
start(_Type, _StartArgs) ->
    digest_auth_sup:start_link().

%% @spec stop(_State) -> ServerRet
%% @doc application stop callback for digest_auth.
stop(_State) ->
    ok.
