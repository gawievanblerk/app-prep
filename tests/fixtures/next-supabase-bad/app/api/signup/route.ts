import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { prisma } from "@/lib/db"

export async function POST(req: Request) {
  const body = await req.json()
  try {
    const user = await prisma.user.create({ data: body })
    cookies().set("session", String(user.id), { path: "/" })
  } catch (err) {
    console.error("signup failed", body)
    return NextResponse.json({ error: "Email already registered" }, { status: 409 })
  }
  return NextResponse.json({ ok: true })
}
