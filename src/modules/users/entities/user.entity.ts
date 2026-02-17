import { ApiHideProperty, ApiProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';
import { User as PrismaUser } from 'generated/prisma/client';

export class User implements Partial<PrismaUser> {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  email!: string;

  @ApiProperty({ type: String })
  username!: string | null;

  @Exclude()
  @ApiHideProperty()
  password!: string;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;

  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
