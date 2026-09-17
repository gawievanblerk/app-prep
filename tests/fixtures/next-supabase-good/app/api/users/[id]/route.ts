import { NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import { auth } from "@/lib/auth"

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth()
  const user = await prisma.user.findUnique({
    where: { id: Number(params.id) },
    select: { id: true, name: true },
  })
  return NextResponse.json(user)
}
