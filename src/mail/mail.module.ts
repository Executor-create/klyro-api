import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailerModule } from '@nestjs-modules/mailer';
import { mailerConfig } from 'src/config/mailer';

@Module({
  imports: [MailerModule.forRootAsync(mailerConfig)],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
