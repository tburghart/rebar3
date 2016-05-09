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

-module(rebar_trace).

-export([init/2, kill/0, running/0, stats/0, format_error/1]).

% tracer process entry point, exported so it can be spawned directly for
% visibility rather than hiding it inside erlang:apply/2
-export([tracer_proc/3]).

-define(TRACER_REG, rebar_tracer).

-type out_dev()         :: {raw, file:fd()} | pid().
-type file_spec()       :: file:filename_all().
-type tracer_state()    :: #state{}.
-type tracer_stat()     :: {atom(), atom() | string()}.
-type tracer_stats()    :: [tracer_stat()].
-type tracer_conf()     :: {atom(), atom() | string()}.
-type tracer_confs()    :: [tracer_conf()].

-record(state, {
    out_dev                         :: out_dev(),
    rebar_pid                       :: pid(),
    trace_count = 0                 :: non_neg_integer(),
    fmt_2       = "~p: ~p~n"        :: string(),
    fmt_3       = "~p: ~p ~p~n"     :: string(),
    fmt_ts_3    = "~p:~p: ~p~n"     :: string(),
    fmt_t3_4    = "~p:~p: ~p ~p~n"  :: string(),
    done_pid    = undefined         :: undefined | pid(),
    done_ref    = undefined         :: undefined | reference(),
    done_reply  = undefined         :: term()
}).

%% ===================================================================
%% Public API
%% ===================================================================

-spec init(State :: rebar_state:t(), Caller :: atom())
        -> rebar_state:t() | {error, term()} | no_return().
%%
%% @doc Installs the trace handler.
%%
init(State, Caller) ->
    case tracer_init(State) of
        {error, _} = Error ->
            handle_init_error(State, Error, Caller);
        _ ->
            State
    end.

-spec kill() -> ok | {error, {?MODULE, term()}}.
%%
%% @doc Shut down the tracer if it's running.
%%
kill() ->
    case tracer_kill(erlang:self()) of
        {error, {?MODULE, _}} = Err ->
            Err;
        {error, Reason} ->
            {error, {?MODULE, Reason}};
        _ ->
            ok
    end.

-spec running() -> boolean().
%%
%% @doc Reports whether the tracer is running.
%%
running() ->
    case erlang:whereis(?TRACER_REG) of
        undefined ->
            false;
        _ ->
            true
    end.

-spec stats() -> {?TRACER_REG, tracer_stats()} | {error, {?MODULE, term()}}.
%%
%% @doc Return the tracer configuration.
%%
stats() ->
    case tracer_stats(erlang:self()) of
        {error, {?MODULE, _}} = Err ->
            Err;
        {error, Reason} ->
            {error, {?MODULE, Reason}};
        Stats ->
            {?TRACER_REG, Stats}
    end.

-spec format_error(Error :: term()) -> string().
%%
%% @doc Converts specified Error to a string.
%%
format_error(Error) ->
    lists:flatten(io_lib:format("~s: ~p", [?MODULE, Error])).

%% ===================================================================
%% Internal
%% ===================================================================

-spec handle_init_error(
    State :: rebar_state:t(), Error :: {error, term()}, Caller :: atom())
        -> rebar_state:t() | {error, {?MODULE, term()}} | no_return().
%
% "Do the right thing" when an initialization error occurs.
% This handles whatever comes out of tracer_init/1.
%
handle_init_error(State, {error, init_timeout = Err}, provider = Caller) ->
    rebar_api:error("~s: ~s failed to start: ~s", [?MODULE, ?TRACER_REG, Err]),
    handle_init_error(State, {error, {?MODULE, Err}}, Caller);

handle_init_error(State, {error, init_timeout}, _Caller) ->
    % this is (presumably) the call from rebar initialization,
    % give it another chance at provider initialization
    State;

handle_init_error(_State, {error, {?MODULE, _}} = Error, provider) ->
    Error;

handle_init_error(_State, {error, {?MODULE, _} = ModErr}, _Caller) ->
    erlang:error(ModErr);

handle_init_error(State, {error, Err}, Caller) ->
    handle_init_error(State, {error, {?MODULE, Err}}, Caller).

-spec tracer_init(State :: rebar_state:t()) -> atom() | {error, term()}.
%
% Maybe start the tracer process.
% Error results must be properly handled by handle_init_error/3.
%
tracer_init(State) ->
    case erlang:whereis(?TRACER_REG) of
        undefined ->
            case rebar_state:get(State, ?TRACER_REG, []) of
                [] ->
                    no_config;
                Config ->
                    rebar_api:debug("~s: Config:~n~p", [?TRACER_REG, Config]),
                    Rebar   = erlang:self(),
                    Starter = Rebar,
                    Tracer  = erlang:spawn(
                        ?MODULE, tracer_proc, [Rebar, Starter, Config]),
                    receive
                        {?TRACER_REG, running, Tracer, Rebar} ->
                            erlang:register(?TRACER_REG, Tracer),
                            ok;
                        {?TRACER_REG, error, Tracer, Error} ->
                            {error, Error}
                    after
                        10000 ->
                            erlang:exit(Tracer, timeout),
                            % error handling depends on this NOT including
                            % the ?MODULE - that is, this precise tuple gets
                            % special handling
                            {error, init_timeout}
                    end
            end;
        _ ->
            ok
    end.

-spec tracer_kill(pid()) -> term().
tracer_kill(ReplyTo) ->
    case erlang:whereis(?TRACER_REG) of
        undefined ->
            not_running;
        Tracer ->
            Tracer ! {'EXIT', ReplyTo, normal},
            receive
                {closed, Tracer, Status} ->
                    Status
            end
    end.

-spec tracer_stats(pid()) -> tracer_stats().
tracer_stats(ReplyTo) ->
    case erlang:whereis(?TRACER_REG) of
        undefined ->
            rebar_api:warn("~s is not running!", [?TRACER_REG]),
            [];
        Tracer ->
            Tracer ! {tracer_stats, ReplyTo},
            receive
                {tracer_stats, Tracer, Stats} ->
                    Stats
            end
    end.

-spec tracer_proc(pid(), pid(), tracer_confs()) -> no_return().
tracer_proc(RebarPid, Starter, Config) ->
    {Gen, File} = case proplists:get_value(trace_file, Config) of
        undefined ->
            {true, gen_output_file()};
        TraceFile ->
            case filelib:ensure_dir(TraceFile) of
                ok ->
                    {false, TraceFile};
                {error, Reason} ->
                    FN  = gen_output_file(),
                    rebar_api:warn(
                        "~s: error ~p creating directory for \"~s\", "
                        "using \"~s\" instead.",
                        [?TRACER_REG, Reason, TraceFile, FN]),
                    {true, FN}
            end
    end,
    Opts = proplists:get_value(trace_opts, Config, [call, return_to]),
    try
        erlang:trace(RebarPid, true, Opts)
    catch
        error:What ->
            rebar_api:abort(
                "~s: fatal error ~p initializing trace with options ~p",
                [?TRACER_REG, What, Opts])
    end,
    erlang:put({?TRACER_REG, trace_opts}, Opts),
    Filters = proplists:get_value(trace_match, Config, []),
    lists:foreach(fun set_trace/1, Filters),
    {OutFile, OutDev} = open_output_file(Gen, File),
    erlang:put({?TRACER_REG, trace_file}, OutFile),
    State = #state{out_dev = OutDev, rebar_pid = RebarPid},
    erlang:process_flag(trap_exit, true),
    erlang:process_flag(priority, high),
    % tell the starter it's running
    Starter ! {?TRACER_REG, running, erlang:self(), RebarPid},
    tracer_recv(State).

-spec set_trace(tuple()) -> term().
%
% add or update the specified trace pattern
%

set_trace({M, F, _} = MFA)
        when erlang:is_atom(M) andalso erlang:is_atom(F) ->
    set_trace({MFA, true});

set_trace({MFA}) ->
    set_trace({MFA, true});

set_trace({MFA, MatchSpec}) ->
    set_trace({MFA, MatchSpec, []});

set_trace({MFA, MatchSpec, Flags} = Filt) ->
    try
        erlang:trace_pattern(MFA, MatchSpec, Flags),
        Filts = case erlang:get({?TRACER_REG, filters}) of
            undefined ->
                [];
            List ->
                proplists:delete(MFA, List)
        end,
        erlang:put({?TRACER_REG, filters}, [{MFA, {MatchSpec, Flags}} | Filts]),
        ok
    catch
        error:What ->
            rebar_api:warn(
                "~s: error ~p setting trace pattern ~p, skipping",
                [?TRACER_REG, What, Filt])
    end.

-spec tracer_recv(State:: tracer_state()) -> no_return().
%
% messages are handled in the order received, no queue filtering
%
tracer_recv(State) ->
    receive
        Msg ->
            handle_msg(State, Msg)
    end.

-spec handle_msg(State:: tracer_state(), tuple()) -> no_return().
%
% handle one received message
%

handle_msg(#state{
        out_dev = OutDev, trace_count = Count, fmt_2 = Format} = State,
        {trace, _Pid, Op, Inf1}) ->
    write_file(OutDev, Format, [Op, Inf1]),
    tracer_recv(State#state{trace_count = (Count + 1)});

handle_msg(#state{
        out_dev = OutDev, trace_count = Count, fmt_3 = Format} = State,
        {trace, _Pid, Op, Inf1, Inf2}) ->
    write_file(OutDev, Format, [Op, Inf1, Inf2]),
    tracer_recv(State#state{trace_count = (Count + 1)});

handle_msg(#state{
        out_dev = OutDev, trace_count = Count, fmt_ts_3 = Format} = State,
        {trace_ts, _Pid, Op, Inf1, TS}) ->
    write_file(OutDev, Format, [Op, TS, Inf1]),
    tracer_recv(State#state{trace_count = (Count + 1)});

handle_msg(#state{
        out_dev = OutDev, trace_count = Count, fmt_t3_4 = Format} = State,
        {trace_ts, _Pid, Op, Inf1, Inf2, TS}) ->
    write_file(OutDev, Format, [Op, TS, Inf1, Inf2]),
    tracer_recv(State#state{trace_count = (Count + 1)});

handle_msg(#state{trace_count = Count} = State, {tracer_stats, ReplyTo}) ->
    Stats = [{count, Count} | tracer_config(erlang:get(), [])],
    ReplyTo ! {tracer_stats, erlang:self(), Stats},
    tracer_recv(State);

handle_msg(#state{
        out_dev = OutDev, rebar_pid = RebarPid,
        done_pid = DonePid, done_ref = DoneRef, done_reply = DoneReply},
        {trace_delivered, RebarPid, DoneRef}) ->
    write_file(OutDev, "Tracing completed.\n"),
    close_file(OutDev),
    DonePid ! {closed, erlang:self(), DoneReply},
    erlang:exit(normal);

handle_msg(#state{rebar_pid = RebarPid} = State, {'EXIT', From, Why}) ->
    Ref = erlang:trace_delivered(RebarPid),
    tracer_recv(State#state{done_pid = From, done_ref = Ref, done_reply = Why});

handle_msg(State, {set_trace, ReplyTo, Spec}) ->
    ReplyTo ! {set_trace, Spec, erlang:self(), set_trace(Spec)},
    tracer_recv(State);

handle_msg(State, Msg) ->
    rebar_api:debug("~s: unhandled message: ~p", [?TRACER_REG, Msg]),
    tracer_recv(State).

-spec tracer_config([{term(), term()}], tracer_stats()) -> tracer_stats().
%
% list filter for tracer process environment entries
%

tracer_config([{{?TRACER_REG, Key}, Val} | Rest], Result) ->
    tracer_config(Rest, [{Key, Val} | Result]);

tracer_config([_KV | Rest], Result) ->
    tracer_config(Rest, Result);

tracer_config([], Result) ->
    Result.

-spec open_output_file(Generated :: boolean(), File :: file_spec())
        -> {file_spec(), out_dev()} | no_return().
%
% open some output file for writing, or die trying
%

open_output_file(false, File) ->
    case open_output_file(File) of
        {ok, IoDev} ->
            {File, IoDev};
        {error, Reason} ->
            FN  = gen_output_file(),
            rebar_api:warn(
                "~s: error ~p opening \"~s\", using \"~s\" instead.",
                [?TRACER_REG, Reason, File, FN]),
            open_output_file(true, FN)
    end;

open_output_file(true, File) ->
    case open_output_file(File) of
        {ok, IoDev} ->
            {File, IoDev};
        {error, Reason} ->
            rebar_api:abort(
                "~s: fatal error ~p opening output file \"~s\".",
                [?TRACER_REG, Reason, File])
            % doesn't return
    end.

gen_output_file() ->
    FN  = io_lib:format("~s.~b", [?TRACER_REG,
            erlang:phash2([erlang:self(), os:timestamp()])]),
    FP  = case filelib:is_dir("/tmp") of
        true ->
            filename:join("/tmp", FN);
        _ ->
            FN
    end,
    lists:flatten(FP).

-spec open_output_file(File :: file_spec()) -> out_dev() | {error, term()}.
%
% Open the specified file for writing.
%
% Try to open in raw mode for direct writes, which should work for any local
% file.  Fall back to using an IO server if it fails, but that probably means
% it's not a local filesystem, and performance will likely be awful.
%
open_output_file(File) ->
    case file:open(File, [write, raw]) of
        {ok, FD} ->
            {ok, {raw, FD}};
        {error, _} ->
            file:open(File, [write])
    end.

-spec close_file(out_dev()) -> ok | {error, term()}.

close_file({raw, FD}) ->
    file:close(FD);

close_file(IoDev) ->
    file:close(IoDev).

-spec write_file(out_dev(), iodata()) -> ok | {error, term()}.

write_file({raw, FD}, Data) ->
    file:write(FD, Data);

write_file(IoDev, Data) ->
    file:write(IoDev, Data).

-spec write_file(out_dev(), io:format(), [term()]) -> ok | {error, term()}.

write_file({raw, FD}, Format, Args) ->
    file:write(FD, io_lib:format(Format, Args));

write_file(IoDev, Format, Args) ->
    io:format(IoDev, Format, Args).
