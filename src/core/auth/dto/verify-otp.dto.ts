import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Length } from 'class-validator';

export class VerifyOtpDto {
  @ApiProperty({ example: '081af48f-cad1-41a5-9216-c88a0a4bc77b' })
  @IsString()
  @IsNotEmpty()
  userId!: string;

  @ApiProperty({ example: '123456' })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp!: string;
}
