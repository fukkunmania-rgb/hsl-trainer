-- ============================================================
-- HSL Trainer — タイムアタック世界ランキング セットアップSQL
--
-- 使い方: Supabase Dashboard の「SQL Editor」でこのファイル全体を
-- 貼り付けて実行してください。テーブル・制約・インデックス・RLS・
-- RPC・権限が一度にセットアップされます。
-- 再実行しても安全なよう idempotent な構成にしています。
-- ============================================================

-- ---------- 1. テーブル ----------
create table if not exists public.time_attack_leaderboard (
  user_id       uuid primary key references auth.users(id) on delete cascade,
  nickname      varchar(16) not null,
  score         integer not null,
  avg_delta_e   double precision not null,
  elapsed_ms    integer not null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),

  constraint ta_score_range      check (score between 0 and 1000),
  constraint ta_avg_delta_e_ok   check (avg_delta_e >= 0 and avg_delta_e <= 200),
  constraint ta_elapsed_ms_ok    check (elapsed_ms >= 0 and elapsed_ms <= 3600000),
  constraint ta_nickname_len     check (char_length(nickname) between 1 and 16)
);

-- ---------- 2. ランキング取得用インデックス ----------
create index if not exists ta_leaderboard_rank_idx
  on public.time_attack_leaderboard (score desc, avg_delta_e asc, elapsed_ms asc, created_at asc);

-- ---------- 3. RLS: テーブルへの直接アクセスを禁止 ----------
-- クライアント(anon/authenticated)にはテーブル操作権限を一切与えず、
-- 記録の登録・取得はすべてRPC経由に限定する。
alter table public.time_attack_leaderboard enable row level security;

revoke all on public.time_attack_leaderboard from anon, authenticated;

-- ---------- 4. 記録登録RPC(自己ベスト比較つき・atomic) ----------
-- ユーザーIDはクライアントから渡さず auth.uid() で取得する。
-- 既存自己ベストより良い場合のみ更新し、常に現在の順位を返す。
create or replace function public.submit_time_attack_score(
  p_nickname     text,
  p_score        integer,
  p_avg_delta_e  double precision,
  p_elapsed_ms   integer
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid      uuid := auth.uid();
  v_nick     text := btrim(p_nickname);
  v_existing public.time_attack_leaderboard%rowtype;
  v_is_better boolean;
  v_rank     bigint;
begin
  if v_uid is null then
    raise exception 'authentication required';
  end if;
  if v_nick is null or char_length(v_nick) < 1 or char_length(v_nick) > 16 then
    raise exception 'invalid nickname';
  end if;
  if p_score is null or p_score not between 0 and 1000 then
    raise exception 'invalid score';
  end if;
  if p_avg_delta_e is null or p_avg_delta_e not between 0 and 200 then
    raise exception 'invalid avg_delta_e';
  end if;
  if p_elapsed_ms is null or p_elapsed_ms not between 0 and 3600000 then
    raise exception 'invalid elapsed_ms';
  end if;

  select * into v_existing
    from public.time_attack_leaderboard
    where user_id = v_uid
    for update;

  v_is_better := not found
    or p_score > v_existing.score
    or (p_score = v_existing.score and p_avg_delta_e < v_existing.avg_delta_e)
    or (p_score = v_existing.score and p_avg_delta_e = v_existing.avg_delta_e
        and p_elapsed_ms < v_existing.elapsed_ms);

  if v_is_better then
    insert into public.time_attack_leaderboard
      (user_id, nickname, score, avg_delta_e, elapsed_ms)
    values
      (v_uid, v_nick, p_score, p_avg_delta_e, p_elapsed_ms)
    on conflict (user_id) do update
      set nickname    = excluded.nickname,
          score       = excluded.score,
          avg_delta_e = excluded.avg_delta_e,
          elapsed_ms  = excluded.elapsed_ms,
          updated_at  = now();
  end if;

  -- 現在の自分の順位を返す(ランキングと同じ優先順位で厳密に数える)
  select count(*) + 1 into v_rank
    from public.time_attack_leaderboard l
    join public.time_attack_leaderboard me on me.user_id = v_uid
    where l.score > me.score
       or (l.score = me.score and l.avg_delta_e < me.avg_delta_e)
       or (l.score = me.score and l.avg_delta_e = me.avg_delta_e
           and l.elapsed_ms < me.elapsed_ms)
       or (l.score = me.score and l.avg_delta_e = me.avg_delta_e
           and l.elapsed_ms = me.elapsed_ms and l.created_at < me.created_at);

  return json_build_object('updated', v_is_better, 'rank', v_rank);
end;
$$;

-- ---------- 5. TOP1000取得RPC ----------
create or replace function public.get_time_attack_top1000()
returns table (
  rank        bigint,
  nickname    text,
  score       integer,
  avg_delta_e double precision,
  elapsed_ms  integer,
  is_me       boolean
)
language sql
security definer
set search_path = public
stable
as $$
  select row_number() over (
           order by l.score desc, l.avg_delta_e asc, l.elapsed_ms asc, l.created_at asc
         ) as rank,
         l.nickname,
         l.score,
         l.avg_delta_e,
         l.elapsed_ms,
         (auth.uid() is not null and l.user_id = auth.uid()) as is_me
    from public.time_attack_leaderboard l
   order by l.score desc, l.avg_delta_e asc, l.elapsed_ms asc, l.created_at asc
   limit 1000;
$$;

-- ---------- 6. 自分の順位取得RPC(TOP1000圏外でも取得可能) ----------
create or replace function public.get_my_time_attack_rank()
returns table (
  rank        bigint,
  nickname    text,
  score       integer,
  avg_delta_e double precision,
  elapsed_ms  integer
)
language sql
security definer
set search_path = public
stable
as $$
  with me as (
    select * from public.time_attack_leaderboard where user_id = auth.uid()
  )
  select (
    select count(*) + 1
      from public.time_attack_leaderboard l
      cross join me
     where l.score > me.score
        or (l.score = me.score and l.avg_delta_e < me.avg_delta_e)
        or (l.score = me.score and l.avg_delta_e = me.avg_delta_e
            and l.elapsed_ms < me.elapsed_ms)
        or (l.score = me.score and l.avg_delta_e = me.avg_delta_e
            and l.elapsed_ms = me.elapsed_ms and l.created_at < me.created_at)
  ) as rank,
  me.nickname, me.score, me.avg_delta_e, me.elapsed_ms
  from me;
$$;

-- ---------- 7. ニックネーム変更RPC(自分の行のみ) ----------
create or replace function public.update_time_attack_nickname(p_nickname text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid  uuid := auth.uid();
  v_nick text := btrim(p_nickname);
begin
  if v_uid is null then
    raise exception 'authentication required';
  end if;
  if v_nick is null or char_length(v_nick) < 1 or char_length(v_nick) > 16 then
    raise exception 'invalid nickname';
  end if;
  update public.time_attack_leaderboard
     set nickname = v_nick, updated_at = now()
   where user_id = v_uid;
end;
$$;

-- ---------- 8. 権限 ----------
-- RPCは authenticated(匿名Authを含む)からのみ実行可能にする。
revoke all on function public.submit_time_attack_score(text, integer, double precision, integer) from public, anon;
revoke all on function public.get_time_attack_top1000() from public, anon;
revoke all on function public.get_my_time_attack_rank() from public, anon;
revoke all on function public.update_time_attack_nickname(text) from public, anon;

grant execute on function public.submit_time_attack_score(text, integer, double precision, integer) to authenticated;
grant execute on function public.get_time_attack_top1000() to authenticated;
grant execute on function public.get_my_time_attack_rank() to authenticated;
grant execute on function public.update_time_attack_nickname(text) to authenticated;
