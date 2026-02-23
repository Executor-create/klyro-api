import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { Injectable, InternalServerErrorException } from '@nestjs/common';

export interface SendEmailParams {
  to: string;
  context: ISendMailOptions['context'];
}

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(params: SendEmailParams): Promise<void> {
    try {
      const { to, context } = params;

      const sendMailParams = {
        to,
        subject: 'Welcome to Klyro!',
        template: 'signup-otp',
        context,
      };

      await this.mailerService.sendMail(sendMailParams);
    } catch (error) {
      throw new InternalServerErrorException(
        'Failed to send confirmation email',
      );
    }
  }
}
