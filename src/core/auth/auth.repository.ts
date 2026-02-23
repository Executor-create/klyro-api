import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class AuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async createOtp(userId: string, otp: string, expiry: Date) {
    await this.prismaService.otp.create({
      data: {
        user_id: userId,
        otp,
        expires_at: expiry,
      },
    });
  }

  async findOtpByUserId(userId: string) {
    return this.prismaService.otp.findFirst({
      where: {
        user_id: userId,
      },
      orderBy: {
        created_at: 'desc',
      },
    });
  }

  async deleteOtpByUserId(userId: string) {
    await this.prismaService.otp.deleteMany({
      where: {
        user_id: userId,
      },
    });
  }
}
