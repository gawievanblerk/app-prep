import { Router } from "express"
import { prisma } from "../lib/db.js"
import { requireUser } from "../middleware/auth.js"

const router = Router()

router.get("/:id", requireUser, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id } })
  if (!order) return res.status(404).json({ error: "Not found" })
  return res.json({ id: order.id, total: order.total })
})

export default router
