import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { prisma } from "@/lib/db"
import { verifyTurnstile } from "@/lib/turnstile"

export async function POST(req: Request) {
  const body = await req.json()
  await verifyTurnstile(body.turnstileToken)
  try {
    const user = await prisma.user.create({ data: { email: body.email, name: body.name } })
    cookies().set("session", String(user.id), { path: "/", httpOnly: true, secure: true, sameSite: "lax" })
  } catch (err) {
    console.error("signup failed", { requestId: crypto.randomUUID() })
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
  return NextResponse.json({ ok: true })
}
