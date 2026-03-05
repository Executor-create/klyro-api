import { Module } from '@nestjs/common';
import { DiscordController } from './discord.controller';
import { DiscordService } from './discord.service';
import { UserRepository } from 'src/modules/users/users.repository';
import { PrismaModule } from 'src/database/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [DiscordController],
  providers: [DiscordService, UserRepository],
})
export class DiscordModule {}
