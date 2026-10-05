-- Zabezpečení databáze Saláty od Kašši.
-- Spustit celé najednou v Supabase → SQL Editor. Lze spustit opakovaně.

begin;

-- ── 0. Sloupce pro potvrzovací e-mail ────────────────────────
-- view_token = tajný klíč v odkazu na rekapitulaci objednávky (order.html?t=…)
alter table public.orders add column if not exists email text;
alter table public.orders add column if not exists view_token uuid not null default gen_random_uuid();
alter table public.orders add column if not exists email_sent_at timestamptz;
create unique index if not exists orders_view_token_key on public.orders (view_token);
-- Koš kopíruje všechny sloupce objednávky, proto je musí mít taky
alter table public.deleted_orders add column if not exists email text;
alter table public.deleted_orders add column if not exists view_token uuid;
alter table public.deleted_orders add column if not exists email_sent_at timestamptz;

-- ── 1. Kdo je admin ──────────────────────────────────────────
-- Admin práva má jen tento e-mail, ne kdokoliv přihlášený.
-- Pro dalšího admina přidej e-mail do seznamu.
create or replace function public.is_admin()
returns boolean
language sql
stable
as $$
  select coalesce(auth.jwt()->>'email', '') in ('mackajo608@gmail.com');
$$;

-- ── 2. Oprávnění veřejnosti (anon) ───────────────────────────
-- Návštěvník smí jen číst produkty a nastavení a vložit objednávku + IP.
revoke all on all tables in schema public from anon;
revoke truncate, references, trigger on all tables in schema public from authenticated;
grant select on public.products, public.shop_settings to anon;
grant insert on public.orders, public.order_ips to anon;

-- ── 3. Pravidla přístupu (RLS) ───────────────────────────────
do $$
declare r record;
begin
  for r in select tablename, policyname from pg_policies where schemaname = 'public' loop
    execute format('drop policy %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;

-- Admin: plný přístup ke všemu
create policy "admin all" on public.orders          for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.deleted_orders  for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.products        for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.customer_groups for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.order_statuses  for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.shop_settings   for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.order_ips       for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin all" on public.blocked_ips     for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Veřejnost
create policy "public read active products" on public.products
  for select to anon using (active = true);

create policy "public read shop_settings" on public.shop_settings
  for select to anon using (true);

create policy "public insert orders" on public.orders
  for insert to anon
  with check (coalesce((select orders_enabled from public.shop_settings where id = 1), true));

create policy "public insert order_ips" on public.order_ips
  for insert to anon
  with check (
    ip ~ '^[0-9A-Fa-f:.]{2,45}$'
    and coalesce(length(user_agent), 0) <= 500
  );

-- ── 4. Číslo objednávky ──────────────────────────────────────
-- security definer: veřejnost nevidí ostatní objednávky, takže by jinak vždy dostala číslo 1.
-- Číslo se nepřepisuje, pokud už je vyplněné (obnovení z koše si ponechá původní).
create or replace function public.set_order_number()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.order_number is null then
    perform pg_advisory_xact_lock(hashtext('orders.order_number'));
    new.order_number := (select coalesce(max(order_number), 0) + 1 from orders);
  end if;
  return new;
end;
$$;

-- ── 5. Kontrola a přepočet objednávky od zákazníka ───────────
-- Ceny, názvy a celkovou cenu z prohlížeče ignoruje a dosadí je z tabulky products.
-- Spouští se před trigger_set_order_number (triggery běží v abecedním pořadí).
create or replace function public.enforce_order_prices()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  delivery_per_item constant numeric := 10;  -- musí odpovídat DELIVERY_PER_ITEM v cart.html a admin.html
  item       jsonb;
  prod       record;
  v          jsonb;
  qty        int;
  unit_price numeric;
  new_items  jsonb   := '[]'::jsonb;
  subtotal   numeric := 0;
  total_qty  int     := 0;
begin
  -- Admin (např. obnovení objednávky z koše) vkládá data beze změny
  if public.is_admin() then
    return new;
  end if;

  if coalesce(trim(new.first_name), '') = '' or coalesce(trim(new.last_name), '') = '' then
    raise exception 'Vyplňte jméno a příjmení.';
  end if;
  if (select phone_required from shop_settings where id = 1) is distinct from false
     and coalesce(trim(new.phone), '') = '' then
    raise exception 'Vyplňte telefon.';
  end if;
  if length(new.first_name) > 100 or length(new.last_name) > 100
     or length(coalesce(new.phone, '')) > 40 or length(coalesce(new.note, '')) > 2000 then
    raise exception 'Některý z údajů je příliš dlouhý.';
  end if;

  new.email := nullif(lower(trim(new.email)), '');
  if new.email is not null and (length(new.email) > 200 or new.email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$') then
    raise exception 'Neplatný e-mail.';
  end if;

  if new.items is null or jsonb_typeof(new.items) <> 'array' or jsonb_array_length(new.items) = 0 then
    raise exception 'Objednávka neobsahuje žádné položky.';
  end if;
  if jsonb_array_length(new.items) > 100 then
    raise exception 'Příliš mnoho položek.';
  end if;

  for item in select * from jsonb_array_elements(new.items) loop
    select id, name, variants into prod
      from products
     where id::text = item->>'productId' and active = true;
    if not found then
      raise exception 'Produkt "%" už není dostupný.', item->>'name';
    end if;

    if coalesce(item->>'qty', '') !~ '^[0-9]{1,4}$' or (item->>'qty')::int < 1 then
      raise exception 'Neplatné množství u produktu "%".', prod.name;
    end if;
    qty := (item->>'qty')::int;

    if jsonb_typeof(prod.variants) = 'array' and jsonb_array_length(prod.variants) > 0 then
      v := null;
      select e into v
        from jsonb_array_elements(prod.variants) e
       where e->>'label' = coalesce(item->>'variant', '')
       limit 1;
      if v is null then
        raise exception 'Varianta "%" u produktu "%" neexistuje.', item->>'variant', prod.name;
      end if;
      unit_price := coalesce((v->>'price')::numeric, 0);
    else
      unit_price := 0;
    end if;

    new_items := new_items || jsonb_build_object(
      'productId', prod.id,
      'name',      prod.name,
      'variant',   coalesce(item->>'variant', ''),
      'qty',       qty,
      'price',     unit_price
    );
    subtotal  := subtotal + unit_price * qty;
    total_qty := total_qty + qty;
  end loop;

  new.items        := new_items;
  new.total_price  := subtotal + total_qty * delivery_per_item;
  new.status       := 'new';
  new.status_id    := null;
  new.group_id     := null;
  new.order_number := null;  -- přidělí trigger_set_order_number
  new.created_at   := now();
  new.view_token    := gen_random_uuid();
  new.email_sent_at := null;
  return new;
end;
$$;

drop trigger if exists enforce_order_prices on public.orders;
create trigger enforce_order_prices
  before insert on public.orders
  for each row execute function public.enforce_order_prices();

-- ── 6. Rekapitulace objednávky přes odkaz z e-mailu ──────────
-- Vrátí jen jednu objednávku a jen tomu, kdo zná její tajný view_token.
create or replace function public.get_order(token uuid)
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'order_number', order_number,
    'created_at',   created_at,
    'first_name',   first_name,
    'last_name',    last_name,
    'phone',        phone,
    'email',        email,
    'note',         note,
    'items',        items,
    'total_price',  total_price
  )
  from orders
  where view_token = token;
$$;

grant execute on function public.get_order(uuid) to anon, authenticated;

commit;
