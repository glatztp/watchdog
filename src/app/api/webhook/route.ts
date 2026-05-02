import { NextRequest } from "next/server";
import { createHmac } from "crypto";
import { runPipeline } from "@/lib/pipeline";

export const runtime = "nodejs";

function verifySignature(payload: string, signature: string): boolean {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return true;

  const expected = `sha256=${createHmac("sha256", secret).update(payload).digest("hex")}`;
  return signature === expected;
}

export async function POST(req: NextRequest) {
  const raw = await req.text();
  const signature = req.headers.get("x-hub-signature-256") ?? "";
  const event = req.headers.get("x-github-event") ?? "";

  if (!verifySignature(raw, signature)) {
    return Response.json({ error: "Invalid signature" }, { status: 401 });
  }

  if (event !== "push" && event !== "create") {
    return Response.json({ skipped: true });
  }

  const payload = JSON.parse(raw);
  const org = payload?.repository?.owner?.login;

  if (!org)
    return Response.json({ error: "No org in payload" }, { status: 400 });

  runPipeline(org, { autoFix: true }).catch((err) =>
    console.error("[watchdog/webhook]", err.message),
  );

  return Response.json({ triggered: true, org });
}
