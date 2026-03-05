import {
  BadRequestException,
  Controller,
  Get,
  Headers,
  Query,
  Redirect,
  UnauthorizedException,
} from '@nestjs/common';
import { DiscordService } from './discord.service';
import { User } from 'src/modules/users/entities/user.entity';

@Controller('auth/discord')
export class DiscordController {
  constructor(private readonly discordService: DiscordService) {}

  @Get('login')
  @Redirect()
  login() {
    const clientId = process.env.DISCORD_CLIENT_ID;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;

    if (!clientId || !redirectUri) {
      throw new Error(
        'Discord configuration is missing in environment variables',
      );
    }

    const url = `https://discord.com/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=identify+email`;

    return { url, statusCode: 302 };
  }

  @Get('callback')
  async getDiscordCallback(@Query('code') code: string): Promise<User> {
    if (!code) {
      throw new BadRequestException('Authorization code is missing');
    }

    const token = await this.discordService.exchangeCodeForToken(code);
    const discordUser = await this.discordService.getDiscordUser(token);
    const user = await this.discordService.findOrCreateUserByEmail(
      discordUser.email,
      discordUser.username,
    );

    console.log(user);

    return user;
  }

  @Get('me')
  async getMe(@Headers('authorization') authHeader: string): Promise<User> {
    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException(
        'Missing or malformed Authorization header',
      );
    }

    const token = authHeader?.replace('Bearer ', '');
    if (!token) {
      throw new Error('Authorization header is missing or malformed');
    }

    const discordUser = await this.discordService.getDiscordUser(token);

    return this.discordService.findOrCreateUserByEmail(
      discordUser.email,
      discordUser.username,
    );
  }
}
