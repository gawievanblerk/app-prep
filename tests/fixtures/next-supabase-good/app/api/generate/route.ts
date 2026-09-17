import OpenAI from "openai"
import { NextResponse } from "next/server"
import { auth } from "@/lib/auth"
import { ratelimit } from "@/lib/ratelimit"

const openai = new OpenAI()

export async function POST(req: Request) {
  if (process.env.GENERATE_ENABLED !== "true") {
    return NextResponse.json({ error: "disabled" }, { status: 503 })
  }
  const session = await auth()
  const { success } = await ratelimit.limit(String(session.user.id))
  if (!success) return NextResponse.json({ error: "slow down" }, { status: 429 })
  const { prompt } = await req.json()
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  })
  return NextResponse.json({ text: completion.choices[0].message.content })
}
