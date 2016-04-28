%% -*- mode: erlang;erlang-indent-level: 4;indent-tabs-mode: nil -*-
%% ========================================================================
%% Copyright (c) 2016 T. R. Burghart
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%% ========================================================================

-module(rebar_prv_trace).

-behaviour(provider).

-export([init/1, do/1, format_error/1]).

%% ===================================================================
%% Provider API
%% ===================================================================

-spec init(State :: rebar_state:t()) -> {ok, rebar_state:t()}.
%
% Installs the trace handler.
%
init(State) ->
    case rebar_trace:init(State) of
        {error, _} = Error ->
            handle_init_error(State, Error);
        {ok, _} = Ret ->
            Ret
    end.

-spec do(State :: rebar_state:t())
        -> {ok, rebar_state:t()} | {error, term()}.
%
% Handle command line.
%
do(State) ->
    case rebar_trace:stats() of
        {error, _} = Err ->
            Err;
        {TracerName, Stats} ->
            [rebar_api:console("~s:~s: ~p", [TracerName, Key, Val])
                || {Key, Val} <- lists:sort(Stats)],
            {ok, State}
    end.

-spec format_error(Error :: term()) -> iolist().
%
% Converts specified Error to a string.
%
format_error(Error) ->
    lists:flatten(io_lib:format("~s: ~p", [?MODULE, Error])).

%% ===================================================================
%% Internal
%% ===================================================================

%
% Unfortunately, init/1 isn't spec'd to allow an error to be returned, so
% whatever this does is the result of that operation.
%
% For now, it reports an error but returns success, though it may be
% preferable to just abort.
%
handle_init_error(State, Error) ->
    ModErr = case Error of
        {error, {Module, Reason}} ->
            [Module, Reason];
        {error, Err} ->
            [?MODULE, Err]
    end,
    rebar_api:error("~s: ~p", ModErr),
    {ok, State}.
