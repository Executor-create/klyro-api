import { ISendMailOptions } from '@nestjs-modules/mailer';
import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';

export interface SendEmailParams {
  to: string;
  subject: string;
  template: string;
  context: ISendMailOptions['context'];
}

@Injectable()
export class MailService {
  constructor(
    @InjectQueue('email-queue') private readonly emailQueue: Queue,
    private readonly configService: ConfigService,
  ) {}

  async sendSignupEmail(
    to: string,
    username: string,
    otp: string,
  ): Promise<void> {
    try {
      const sendMailParams = {
        to,
        subject: 'Signup Confirmation',
        template: 'signup-otp',
        context: { username, otp },
      };
      await this.emailQueue.add('send-email', sendMailParams, {
        attempts: 3,
        backoff: 5000,
      });
    } catch (error) {
      throw new InternalServerErrorException('Failed to send signup email');
    }
  }

  async sendForgotPasswordEmail(
    to: string,
    username: string,
    token: string,
  ): Promise<void> {
    try {
      const reset_url = `${this.configService.get('FRONTEND_URL')}/reset-password?token=${token}`;

      const sendMailParams = {
        to,
        subject: 'Reset Your Password',
        template: 'forgot-password',
        context: { username, reset_url },
      };
      await this.emailQueue.add('send-email', sendMailParams, {
        attempts: 3,
        backoff: 5000,
      });
    } catch (error) {
      throw new InternalServerErrorException(
        'Failed to send forgot password email',
      );
    }
  }

  async sendEmail(params: SendEmailParams): Promise<void> {
    try {
      const { to, template, subject, context } = params;

      const sendMailParams = {
        to,
        subject,
        template,
        context,
      };

      await this.emailQueue.add('send-email', sendMailParams, {
        attempts: 3,
        backoff: 5000,
      });
    } catch (error) {
      throw new InternalServerErrorException('Failed to send email');
    }
  }
}
