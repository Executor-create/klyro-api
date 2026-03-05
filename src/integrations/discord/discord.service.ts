import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { User } from 'src/modules/users/entities/user.entity';
import { UserRepository } from 'src/modules/users/users.repository';

interface DiscordUser {
  id: string;
  username: string;
  email: string;
  avatar: string | null;
  discriminator: string;
}

@Injectable()
export class DiscordService {
  constructor(private readonly userRepository: UserRepository) {}

  async exchangeCodeForToken(code: string): Promise<string> {
    const clientId = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;

    if (!clientId || !clientSecret || !redirectUri) {
      throw new InternalServerErrorException(
        'Discord configuration is missing',
      );
    }

    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    });

    const resp = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      body: body.toString(),
    });

    if (!resp.ok) {
      const errorData = await resp.json();
      console.error('Discord token exchange failed:', errorData);
      throw new InternalServerErrorException(
        'Failed to exchange Discord token',
      );
    }

    const json = await resp.json();
    return json.access_token;
  }

  async getDiscordUser(token: string): Promise<DiscordUser> {
    const resp = await fetch('https://discord.com/api/v10/users/@me', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!resp.ok) {
      const errorData = await resp.json();
      console.error('Discord user fetch failed:', errorData);
      throw new InternalServerErrorException('Failed to fetch Discord user');
    }

    return resp.json();
  }

  async findOrCreateUserByEmail(
    email: string,
    username: string,
  ): Promise<User> {
    const existing = await this.userRepository.findByEmail(email);
    if (existing) return existing;

    const created = await this.userRepository.create({
      email,
      username,
      password: null,
    });
    if (!created)
      throw new InternalServerErrorException('User creation failed');

    return created;
  }
}
