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

-define(PROVIDER_REG,   rebar_tracer).
-define(PROVIDER_STR,   "rebar_tracer").

-define(PROVIDER_MOD,   ?MODULE).
-define(TRACER_MOD,     rebar_trace).

-define(SHORT_DESC,     "Rebar Tracer, for development ONLY").
-define(LONG_DESC,      ?SHORT_DESC "!

Important:
 - Tracing is global, regardless of the profile it's configured in!
 - Tracing is heavyweight, use it ONLY for debugging!
 - Tracing WILL slow rebar down, possibly a LOT!

Configuration:
  The presence of the " ?PROVIDER_STR " configuration stanza in rebar.config
  enables tracing functionality. If the configuration is not present, the
  tracer is not initialized and has no effect. Recognized configuration
  elements are as follows:

{" ?PROVIDER_STR ", [
    {trace_file,    \"my_trace.txt\"},
    {trace_opts,    [call, return_to]},
    {trace_match,   [
        {rebar_core, '_', '_'},
        {{my_plugin, '_', '_'}, true, [local]}
    ]}
]}.

'trace_file':
  If specified, the path to the file into which trace records are written.
  If not specified, a file name is generated as \"/tmp/" ?PROVIDER_STR ".NNN\"
  (or in the current directory if for some reason '/tmp' isn't writable), where
  NNN is a fairly random number.
  Be aware that the trace file can easily reach dozens of megabytes in size,
  especially when tracing calls that include a rebar_state:t() record.

'trace_opts':
  Options to be passed in the 3rd parameter of erlang:trace/3.
  If not specified, options shown in the example above are the default.
  The 1st and 2nd parameters to erlang:trace/3 are Rebar's Pid and 'true',
  respectively.
  The tracing process itself runs under a separate Pid and is not traceable
  through this facility, though of course its external API is.

'trace_match':
  The list of match specifications provided to erlang:trace_pattern/3.
  If not specified, the tracer process will run, and the trace file will be
  created, but the facility will effectively be dormant unless match
  specifications are added dynamically (not covered here).
  Each pattern consists of a tuple with 1, 2, or 3 elements, with the 2nd and
  3rd elements defaulting to 'true' and '[]' if not supplied. As a special
  case, a standalone MFA tuple will be effectively wrapped in '{}' and treated
  as above.
  WARNING: Specifying a match pattern of {'_', '_', '_'} is a VERY BAD IDEA and
  WILL bring rebar to its knees!

References:
 - http://erlang.org/doc/man/erlang.html#trace-3
 - http://erlang.org/doc/man/erlang.html#trace_pattern-3
 - http://erlang.org/doc/apps/erts/match_spec.html

Command Line:
  The only supported command-line usage is simply \"" ?PROVIDER_STR "\", which
  displays the current configuration and any statistics that may be gathered.
").

%% ===================================================================
%% Provider API
%% ===================================================================

-spec init(State :: rebar_state:t()) -> {ok, rebar_state:t()}.
%
% Installs the trace handler.
%
init(State) ->
    %
    % Alas, the #provider{} record isn't publicly defined, but we know the
    % first two fields after the record tag are the name and module.
    %
    case lists:keyfind(?PROVIDER_REG, 2, rebar_state:providers(State)) of
        false ->
            % maybe not initialized yet
            case ?TRACER_MOD:init(State, provider) of
                {error, _} = Error ->
                    handle_init_error(State, Error);
                NewState ->
                    case ?TRACER_MOD:running() orelse lists:any(
                            fun env_var_not_empty/1, ["DEBUG", "TRACE"]) of
                        true ->
                            %
                            % install the provider even if the tracer itself
                            % isn't configured so it'll show up in help
                            %
                            Prov = providers:create([
                                {name,          ?PROVIDER_REG},
                                {module,        ?PROVIDER_MOD},
                                {bare,          true},
                                {deps,          []},
                                {example,       example(State)},
                                {opts,          []},
                                {short_desc,    ?SHORT_DESC},
                                {desc,          ?LONG_DESC}
                            ]),
                            {ok, rebar_state:add_provider(NewState, Prov)};
                        _ ->
                            {ok, NewState}
                    end
            end;
        Reg ->
            case erlang:element(3, Reg) of
                ?PROVIDER_MOD ->
                    ok;
                Mod ->
                    rebar_api:warn(
                        "provider '~s' already installed as module '~s', "
                        "skipping install as module '~s'",
                        [?PROVIDER_REG, Mod, ?PROVIDER_MOD])
            end,
            {ok, State}
    end.

-spec do(State :: rebar_state:t())
        -> {ok, rebar_state:t()} | {error, {module(), term()}}.
%
% Handle command line.
%
do(State) ->
    case ?TRACER_MOD:stats() of
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

-spec env_var_not_empty(Var :: string()) -> boolean().
env_var_not_empty(Var) ->
    case os:getenv(Var) of
        [_ | _] ->
            true;
        _ ->
            false
    end.

-spec example(State :: rebar_state:t()) -> string().
example(State) ->
    Exec = case rebar_state:escript_path(State) of
        undefined ->
            "rebar3";
        Path ->
            lists:last(filename:split(Path))
    end,
    lists:flatten(io_lib:format("~s ~s", [Exec, ?PROVIDER_REG])).

-spec handle_init_error(State :: rebar_state:t(), Error :: {error, term()})
        -> {ok, rebar_state:t()} | no_return().
%
% Unfortunately, init/1 isn't spec'd to allow an error to be returned, so
% this doesn't really have any options other than an exception or abort.
%
% dialyzer may complain that some of these patterns are never matched, but
% removing them would make the code more brittle than I'd like because it'd
% be subject to xxx_clause errors with even trivial changes to the
% initialization code
%
handle_init_error(_State, Error) ->
    ModErr = case Error of
        {error, {?PROVIDER_MOD, _} = Err} ->
            Err;
        {error, {?TRACER_MOD, _} = Err} ->
            Err;
        {error, Err} ->
            {?MODULE, Err}
    end,
    erlang:error(ModErr).
