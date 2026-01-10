import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: parseInt(process.env.MAIL_PORT || '465', 10),
      secure: true, // true for 465, false for 587
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD,
      },
    });
  }

  async sendMail({ to, subject, text, html }: { to: string; subject: string; text: string; html?: string }) {
    const info = await this.transporter.sendMail({
      from: `"Switchgate" <${process.env.MAIL_USER}>`,
      to,
      subject,
      text,
      html,
    });

    return info;
  } catch (err) {
    throw new Error('Email delivery failed: ${err.message}');
  }
}