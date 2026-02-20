import { Injectable } from '@nestjs/common';
import { User } from 'src/modules/users/entities/user.entity';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  async updateUserToken(userId: string, token: string): Promise<User> {
    return this.prisma.user.update({
      where: { id: userId },
      data: { token },
    });
  }
}
