import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class ResendOtpDto {
  @ApiProperty({ example: '081af48f-cad1-41a5-9216-c88a0a4bc77b' })
  @IsString()
  @IsNotEmpty()
  userId!: string;
}
