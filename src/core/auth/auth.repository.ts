import { Injectable } from '@nestjs/common';
import { Prisma, User } from 'generated/prisma/client';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  async createUser(user: Prisma.UserCreateInput): Promise<User | null> {
    return this.prisma.user.create({
      data: user,
    });
  }
}
