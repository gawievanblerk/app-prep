import express from "express"
import orderRoutes from "./routes/orders.js"
import authRoutes from "./routes/auth.js"

const app = express()
app.disable("x-powered-by")
app.use(express.json())
app.use("/api/orders", orderRoutes)
app.use("/api/auth", authRoutes)

app.listen(3000)
