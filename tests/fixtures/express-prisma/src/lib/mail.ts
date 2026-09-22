import nodemailer from "nodemailer"

const transport = nodemailer.createTransport({ host: process.env.SMTP_HOST })

export async function sendMail(to: string, subject: string, text: string) {
  await transport.sendMail({ to, subject, text })
}
