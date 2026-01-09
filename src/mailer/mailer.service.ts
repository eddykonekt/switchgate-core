import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '465', 10),
      secure: true, // true for 465, false for 587
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async sendMail({ to, subject, text, html }: { to: string; subject: string; text: string; html?: string }) {
    const info = await this.transporter.sendMail({
      from: `"Switchgate" <${process.env.SMTP_USER}>`,
      to,
      subject,
      text,
      html,
    });

    return info;
  }
}