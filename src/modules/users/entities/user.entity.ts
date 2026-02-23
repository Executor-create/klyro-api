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

  @ApiProperty()
  is_verified!: boolean;

  @Exclude()
  @ApiHideProperty()
  refresh_token?: string | null;

  @ApiProperty()
  created_at!: Date;

  @ApiProperty()
  updated_at!: Date;

  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
