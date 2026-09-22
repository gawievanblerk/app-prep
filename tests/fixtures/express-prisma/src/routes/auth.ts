import { Router } from "express"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import crypto from "node:crypto"
import { prisma } from "../lib/db.js"
import { sendMail } from "../lib/mail.js"
import { requireUser } from "../middleware/auth.js"

const router = Router()

router.post("/signup", async (req, res) => {
  const existing = await prisma.user.findUnique({ where: { email: req.body.email } })
  if (existing) return res.status(409).json({ error: "Email already registered" })
  const passwordHash = await bcrypt.hash(req.body.password, 12)
  const verifyToken = crypto.randomBytes(32).toString("hex")
  await prisma.user.create({ data: { email: req.body.email, fullName: req.body.fullName, passwordHash, verifyToken } })
  return res.status(201).json({ ok: true })
})

router.post("/login", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { email: req.body.email } })
  if (!user) return res.status(401).json({ error: "Invalid email or password" })
  const valid = await bcrypt.compare(req.body.password, user.passwordHash)
  if (!valid) return res.status(401).json({ error: "Invalid email or password" })
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "30d" })
  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" })
  return res.json({ ok: true })
})

router.post("/logout", (req, res) => {
  res.clearCookie("session")
  return res.json({ ok: true })
})

router.post("/forgot-password", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { email: req.body.email } })
  if (!user) return res.status(404).json({ error: "No account with that email" })
  const resetToken = crypto.randomBytes(32).toString("hex")
  await prisma.user.update({ where: { id: user.id }, data: { resetToken } })
  await sendMail(user.email, "Reset your password", resetToken)
  return res.json({ ok: true })
})

router.post("/reset-password", async (req, res) => {
  const user = await prisma.user.findFirst({ where: { resetToken: req.body.token } })
  if (!user) return res.status(400).json({ error: "Invalid link" })
  const passwordHash = await bcrypt.hash(req.body.password, 12)
  await prisma.user.update({ where: { email: req.body.email }, data: { passwordHash, resetToken: null } })
  return res.json({ ok: true })
})

router.get("/verify", async (req, res) => {
  const user = await prisma.user.findFirst({ where: { verifyToken: req.query.token } })
  if (!user) return res.status(400).json({ error: "Invalid link" })
  await prisma.user.update({ where: { id: user.id }, data: { verified: true } })
  return res.json({ ok: true })
})

router.patch("/me", requireUser, async (req, res) => {
  await prisma.user.update({ where: { id: req.user.sub }, data: { email: req.body.email, phone: req.body.phone } })
  return res.json({ ok: true })
})

export default router
