import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { User } from './entities/user.entity';
import { Prisma } from 'generated/prisma/client';

@Injectable()
export class UserRepository {
  constructor(private readonly prisma: PrismaService) {}

  async create(user: Prisma.UserCreateInput): Promise<User | null> {
    return this.prisma.user.create({
      data: user,
    });
  }

  async findByIdOrThrow(id: string): Promise<User | null> {
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id },
    });

    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    return user;
  }

  async findByEmailOrThrow(email: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    return user;
  }

  async update(id: string, data: Prisma.UserUpdateInput): Promise<User> {
    return this.prisma.user.update({
      where: { id },
      data,
    });
  }
}
