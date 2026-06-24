// Supabase Edge Function — Stripe Webhook Handler
// Deploy: supabase functions deploy stripe-webhook
// Set secrets: supabase secrets set STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_SECRET_KEY=sk_live_...

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY") ?? "", {
  apiVersion: "2024-04-10",
  httpClient: Stripe.createFetchHttpClient(),
});

const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
);

const TIER_MAP: Record<string, string> = {
  [Deno.env.get("STRIPE_PRICE_STARTER") ?? ""]:       "starter",
  [Deno.env.get("STRIPE_PRICE_PROFESSIONAL") ?? ""]:  "professional",
  [Deno.env.get("STRIPE_PRICE_ENTERPRISE") ?? ""]:    "enterprise",
};

serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  const body = await req.text();

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      sig!,
      Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? ""
    );
  } catch (err) {
    console.error("Webhook signature failed:", err.message);
    return new Response(JSON.stringify({ error: "Invalid signature" }), { status: 400 });
  }

  try {
    switch (event.type) {

      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const customerEmail = session.customer_email ?? session.customer_details?.email;
        const tier = session.metadata?.tier ?? "starter";
        const customerId = session.customer as string;
        if (customerEmail) {
          await updateUserTier(customerEmail, tier, customerId);
          console.log(`Upgraded ${customerEmail} → ${tier}`);
        }
        break;
      }

      case "customer.subscription.updated": {
        const sub = event.data.object as Stripe.Subscription;
        const priceId = sub.items.data[0]?.price?.id ?? "";
        const tier = TIER_MAP[priceId] ?? "free";
        const customer = await stripe.customers.retrieve(sub.customer as string) as Stripe.Customer;
        if (customer.email) {
          await updateUserTier(customer.email, tier, sub.customer as string);
        }
        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object as Stripe.Subscription;
        const customer = await stripe.customers.retrieve(sub.customer as string) as Stripe.Customer;
        if (customer.email) {
          await updateUserTier(customer.email, "free", sub.customer as string);
          console.log(`Downgraded ${customer.email} → free`);
        }
        break;
      }

      case "invoice.payment_failed": {
        const inv = event.data.object as Stripe.Invoice;
        const customer = await stripe.customers.retrieve(inv.customer as string) as Stripe.Customer;
        console.warn(`Payment failed for ${customer.email}`);
        // Optionally send email via Supabase trigger
        break;
      }
    }
  } catch (err) {
    console.error("Handler error:", err);
    return new Response(JSON.stringify({ error: "Handler failed" }), { status: 500 });
  }

  return new Response(JSON.stringify({ received: true }), { status: 200 });
});

async function updateUserTier(email: string, tier: string, stripeCustomerId: string) {
  const { error } = await supabase
    .from("profiles")
    .update({
      subscription_tier: tier,
      stripe_customer_id: stripeCustomerId,
      subscription_expires_at: tier === "free" ? null : getNextMonth(),
    })
    .eq("email", email.toLowerCase());

  if (error) {
    console.error("Supabase update error:", error);
    throw error;
  }
}

function getNextMonth(): string {
  const d = new Date();
  d.setMonth(d.getMonth() + 1);
  return d.toISOString();
}
