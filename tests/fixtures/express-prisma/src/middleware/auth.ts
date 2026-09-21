import jwt from "jsonwebtoken"

export function requireUser(req, res, next) {
  const token = req.cookies?.session
  if (!token) return res.status(401).json({ error: "Sign in" })
  req.user = jwt.verify(token, process.env.JWT_SECRET)
  next()
}
