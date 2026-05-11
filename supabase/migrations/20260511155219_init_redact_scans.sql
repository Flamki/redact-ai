create table if not exists redact_scans (
    id uuid default gen_random_uuid() primary key,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null,
    source text not null,
    entity_count integer default 0,
    types jsonb default '[]'::jsonb,
    processing_ms integer default 0,
    preview text,
    user_id uuid
);

-- set up row level security
alter table redact_scans enable row level security;

create policy "Enable read access for all users" on redact_scans
    for select using (true);

create policy "Enable insert for all users" on redact_scans
    for insert with check (true);
