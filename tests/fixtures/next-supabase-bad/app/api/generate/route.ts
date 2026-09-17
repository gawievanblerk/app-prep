import OpenAI from "openai"
import { NextResponse } from "next/server"

const openai = new OpenAI()

export async function POST(req: Request) {
  const { prompt } = await req.json()
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  })
  return NextResponse.json({ text: completion.choices[0].message.content })
}
