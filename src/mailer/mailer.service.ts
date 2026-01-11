// src/mailer/mailer.service.ts
import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import * as fs from 'fs';
import * as path from 'path';
import * as Handlebars from 'handlebars';

@Injectable()
export class AppMailer {
  static sendWelcomeEmail: any;
  constructor(private readonly mailer: MailerService) {}

  // Utility: compile a Handlebars template file
  private compileTemplate(templatePath: string, context: any): string {
    const file = fs.readFileSync(path.join(__dirname, 'templates', templatePath), 'utf8');
    const template = Handlebars.compile(file);
    return template(context);
  }

  async sendOtpEmail(userName: string, email: string, otp: string) {
    const html = this.compileTemplate('otp/otp.html.hbs', { userName, otp });
    const text = this.compileTemplate('otp/otp.txt.hbs', { userName, otp });

    await this.mailer.sendMail({
      to: email,
      subject: 'Your One Time Password (OTP)',
      html,
      text,
    });
  }

  async sendWelcomeEmail(userName: string, email: string, verifyUrl: string) {
    const html = this.compileTemplate('welcome/welcome.html.hbs', { userName, verifyUrl });
    const text = this.compileTemplate('welcome/welcome.txt.hbs', { userName, verifyUrl });

    await this.mailer.sendMail({
      to: email,
      subject: 'Welcome to Switchgate',
      html,
      text,
    });
  }

  async sendClientWelcomeEmail(
    clientName: string,
    email: string,
    clientId: string,
    clientSecret: string,
    apiKey: string,
    clientType: string,
  ) {
    const html = this.compileTemplate('client/client.html.hbs', {
      clientName,
      clientId,
      clientSecret,
      apiKey,
      clientType,
    });
    const text = this.compileTemplate('client/client.txt.hbs', {
      clientName,
      clientId,
      clientSecret,
      apiKey,
      clientType,
    });

    await this.mailer.sendMail({
      to: email,
      subject: `Welcome to Switchgate (${clientType} Credentials)`,
      html,
      text,
    });
  }
}

export { MailerService };
