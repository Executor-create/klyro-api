import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailerModule } from '@nestjs-modules/mailer';
import { mailerConfig } from 'src/config/mailer';
import { BullModule } from '@nestjs/bullmq';
import { MailConsumer } from './workers/mailWorker';

@Module({
  imports: [
    MailerModule.forRootAsync(mailerConfig),
    BullModule.registerQueue({
      name: 'email-queue',
    }),
  ],
  providers: [MailService, MailConsumer],
  exports: [MailService],
})
export class MailModule {}
