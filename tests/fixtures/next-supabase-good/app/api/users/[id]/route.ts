import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  if (!session || String(session.user.id) !== params.id) {
    return NextResponse.json({ error: "not found" }, { status: 404 })
  }
  const user = await prisma.user.findUnique({
    where: { id: Number(session.user.id) },
    select: { id: true, name: true },
  })
  return NextResponse.json(user)
}
