import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function POST(req: Request) {
  const body = await req.json()
  try {
    await prisma.user.create({ data: { email: body.email, name: body.name } })
  } catch (err) {
    console.error("signup failed", { requestId: crypto.randomUUID() })
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
  return NextResponse.json({ ok: true })
}
