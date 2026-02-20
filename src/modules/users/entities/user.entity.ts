import { ApiHideProperty, ApiProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';
import { User as PrismaUser } from 'generated/prisma/client';

export class User implements Partial<PrismaUser> {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  email!: string;

  @ApiProperty({ type: String })
  username!: string;

  @Exclude()
  @ApiHideProperty()
  password!: string;

  @Exclude()
  @ApiHideProperty()
  refreshToken?: string | null;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;

  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
