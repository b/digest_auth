%% @author Benjamin Black <b@b3k.us>
%% @copyright 2011 Benjamin Black.

%% @doc Digest auth example resource.

-module(digest_auth_resource).
-export([init/1, is_authorized/2, to_html/2, get_password/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(state, {realm, params}).

init([]) -> {ok, #state{realm="testrealm@b3k.us"}}.

is_authorized(ReqData, State=#state{realm=Realm}) ->
  Response = digest_auth:is_authorized(ReqData, Realm, fun ?MODULE:get_password/2),
  {Response, ReqData, State}.
  
to_html(ReqData, State) ->
  {"<html><body>Hello, new world</body></html>", ReqData, State}.

get_password(_Realm, Username) ->
  proplists:get_value(Username, [
    {"foo", "bar"}, {"baz", "bal"}
  ]).
