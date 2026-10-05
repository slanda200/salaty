// Odešle potvrzovací e-mail k objednávce přes Gmail.
// Volá ji cart.html hned po odeslání objednávky s { orderId }.
// Každá objednávka dostane mail nejvýš jednou a jen do 15 minut od vytvoření,
// takže funkci nejde zneužít k opakovanému posílání.
//
// Potřebné secrets (Supabase → Edge Functions → Secrets):
//   GMAIL_USER          – Gmail adresa obchodu
//   GMAIL_APP_PASSWORD  – heslo pro aplikace z účtu Google
//   SITE_URL            – adresa webu, např. https://slanda200.github.io/salaty

import { createClient } from "npm:@supabase/supabase-js@2";
import nodemailer from "npm:nodemailer@6";

const DELIVERY_PER_ITEM = 10;

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

function esc(v: unknown) {
  return String(v ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

type Item = { name: string; variant?: string; qty: number; price: number };

function emailHTML(o: Record<string, any>, link: string) {
  const items: Item[] = Array.isArray(o.items) ? o.items : [];
  const totalQty = items.reduce((s, i) => s + (i.qty || 0), 0);
  const delivery = totalQty * DELIVERY_PER_ITEM;

  const rows = items.map((i) => `
    <tr>
      <td style="padding:8px 0;border-bottom:1px solid #eee">
        <strong>${esc(i.name)}</strong>${i.variant ? ` <span style="color:#777">(${esc(i.variant)})</span>` : ""}<br>
        <span style="color:#777;font-size:13px">${esc(i.qty)} × ${esc(i.price)} Kč</span>
      </td>
      <td style="padding:8px 0;border-bottom:1px solid #eee;text-align:right;white-space:nowrap">
        <strong>${esc(i.qty * i.price)} Kč</strong>
      </td>
    </tr>`).join("");

  return `
  <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#222">
    <h2 style="color:#3f7856;margin-bottom:4px">Děkujeme za objednávku!</h2>
    <p style="margin-top:0;color:#555">Objednávka č. <strong>${esc(o.order_number)}</strong> byla přijata.</p>

    <table style="width:100%;border-collapse:collapse;margin:16px 0">
      ${rows}
      <tr><td style="padding:8px 0;color:#555">Doprava</td><td style="padding:8px 0;text-align:right">${esc(delivery)} Kč</td></tr>
      <tr><td style="padding:8px 0;font-size:18px"><strong>Celkem</strong></td>
          <td style="padding:8px 0;text-align:right;font-size:18px;color:#3f7856"><strong>${esc(o.total_price)} Kč</strong></td></tr>
    </table>

    <p style="color:#555;line-height:1.6">
      <strong>${esc(o.first_name)} ${esc(o.last_name)}</strong><br>
      ${o.phone ? `${esc(o.phone)}<br>` : ""}
      ${o.note ? `Poznámka: ${esc(o.note)}` : ""}
    </p>

    <p style="text-align:center;margin:28px 0">
      <a href="${esc(link)}" style="background:#3f7856;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:bold;display:inline-block">
        Zobrazit objednávku
      </a>
    </p>
    <p style="color:#999;font-size:12px;text-align:center">Saláty od Kašši</p>
  </div>`;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const { orderId } = await req.json().catch(() => ({}));
  if (typeof orderId !== "string" || !/^[0-9a-f-]{36}$/i.test(orderId)) {
    return json({ error: "Neplatné ID objednávky" }, 400);
  }

  const db = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  // Zarezervuj odeslání (atomicky) — jen pokud mail ještě neodešel
  const { data: order, error } = await db
    .from("orders")
    .update({ email_sent_at: new Date().toISOString() })
    .eq("id", orderId)
    .is("email_sent_at", null)
    .not("email", "is", null)
    .gte("created_at", new Date(Date.now() - 15 * 60 * 1000).toISOString())
    .select()
    .maybeSingle();

  if (error) return json({ error: error.message }, 500);
  if (!order) return json({ sent: false });

  const siteUrl = (Deno.env.get("SITE_URL") || "").replace(/\/$/, "");
  const link = `${siteUrl}/order.html?t=${order.view_token}`;
  const gmailUser = Deno.env.get("GMAIL_USER")!;

  try {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: { user: gmailUser, pass: Deno.env.get("GMAIL_APP_PASSWORD")! },
    });
    await transporter.sendMail({
      from: `"Saláty od Kašši" <${gmailUser}>`,
      to: order.email,
      subject: `Potvrzení objednávky č. ${order.order_number}`,
      html: emailHTML(order, link),
    });
  } catch (e) {
    // Mail neodešel — uvolni rezervaci, ať jde zkusit znovu
    await db.from("orders").update({ email_sent_at: null }).eq("id", orderId);
    return json({ error: String(e) }, 500);
  }

  return json({ sent: true });
});
