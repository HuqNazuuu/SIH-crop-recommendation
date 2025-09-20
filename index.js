import express from 'express'
import 'express-async-errors'

const app = express()

import { config } from 'dotenv'
import { connectDB } from './config/db.js'

import notFoundMiddleware from './middleware/not-found.js'
import errorHandlerMiddleware from './middleware/error-handler.js'
import authRouter from './routes/auth.js'
import cors from 'cors'
import cookieParser from 'cookie-parser'

config()

app.use(express.json())
app.use(cookieParser())
/*app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true, // Allow cookies to be sent
  })
)
*/
app.use('/api/v1/auth', authRouter)

app.use(notFoundMiddleware)
app.use(errorHandlerMiddleware)
const start = async () => {
  try {
    await connectDB()
    app.listen(process.env.PORT, () => {
      console.log(
        `Server is listening or running on port ${process.env.PORT}...`
      )
    })
  } catch (error) {
    console.error(`Error: ${error.message}`)
    process.exit(1)
  }
}
start()
