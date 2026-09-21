import express from "express"
import orderRoutes from "./routes/orders.js"

const app = express()
app.disable("x-powered-by")
app.use(express.json())
app.use("/api/orders", orderRoutes)

app.listen(3000)
