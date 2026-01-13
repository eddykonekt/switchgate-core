import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AppMailer {
  private transporter;
  mailerService: any;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async sendWelcomeEmail(email: string, link: string) {
    await this.transporter.sendMail({
      from: '"Switchgate" <no-reply@switchgate.com>',
      to: email,
      subject: 'Welcome to Switchgate',
      html: `<p>Welcome! Please verify your account:</p><p><a href="${link}">${link}</a></p>`,
    });
  }

  async sendOtpEmail(email: string, otp: string) {
    await this.transporter.sendMail({
      from: '"Switchgate" <no-reply@switchgate.com>',
      to: email,
      subject: 'Your OTP Code',
      html: `<p>Your OTP code is <b>${otp}</b>. It expires in 5 minutes.</p>`,
    });
  }

  async sendClientWelcomeEmail(email: string, clientId: string, clientSecret: string, apiKey: string, role: string) {
    await this.transporter.sendMail({
      from: '"Switchgate" <no-reply@switchgate.com>',
      to: email,
      subject: 'Your Client Credentials',
      html: `
        <p>Hello,</p>
        <p>Your ${role} client has been registered successfully.</p>
        <p><b>Client ID:</b> ${clientId}</p>
        <p><b>Client Secret:</b> ${clientSecret}</p>
        <p><b>API Key:</b> ${apiKey}</p>
      `,
    });
  }

  async sendVerificationEmail(email: string, token: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Verify Your Account',
      template: './verify',
      context: { token },
    });
  }
}