import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

const ALLOWED_ORIGINS = ["https://app.example.com"]

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  const invoice = await prisma.invoice.findFirst({
    where: { id: Number(params.id), userId: session.user.id },
    select: { amount: true },
  })
  return withCors(req, NextResponse.json({ amount: invoice?.amount }))
}

function withCors(req: Request, res: Response) {
  const origin = req.headers.get("origin")
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.headers.set("Access-Control-Allow-Origin", origin)
  }
  return res
}
