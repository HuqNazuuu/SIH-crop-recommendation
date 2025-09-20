import nodemailer from 'nodemailer'
import { config } from 'dotenv'

config()
export const transporter = nodemailer.createTransport({
  service: 'gmail',
  secure: true,
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD, // app-specific password
  },
})
