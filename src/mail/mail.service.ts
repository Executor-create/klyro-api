import { ISendMailOptions } from '@nestjs-modules/mailer';
import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { Queue } from 'bullmq';

export interface SendEmailParams {
  to: string;
  subject: string;
  template: string;
  context: ISendMailOptions['context'];
}

@Injectable()
export class MailService {
  constructor(@InjectQueue('email-queue') private readonly emailQueue: Queue) {}

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
