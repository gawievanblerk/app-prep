import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  const invoice = await prisma.invoice.findUnique({ where: { id: Number(params.id) } })
  return withCors(req, NextResponse.json({ amount: invoice?.amount }))
}

function withCors(req: Request, res: Response) {
  res.headers.set("Access-Control-Allow-Origin", req.headers.get("origin") ?? "")
  res.headers.set("Access-Control-Allow-Credentials", "true")
  return res
}
