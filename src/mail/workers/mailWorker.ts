import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { MailerService } from '@nestjs-modules/mailer';

@Processor('email-queue')
export class MailConsumer extends WorkerHost {
  constructor(private readonly mailService: MailerService) {
    super();
  }

  async process(job: Job): Promise<void> {
    const { to, template, subject, context } = job.data;
    await this.mailService.sendMail({
      to,
      template,
      subject,
      context,
    });
  }
}
