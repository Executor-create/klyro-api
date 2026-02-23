import { ApiProperty } from '@nestjs/swagger';
import { User } from 'src/modules/users/entities/user.entity';

export class SignUpResponse {
  @ApiProperty()
  message!: string;

  @ApiProperty()
  userId!: string;
}

export class AuthResponse {
  @ApiProperty()
  accessToken!: string;

  @ApiProperty()
  refreshToken!: string;

  @ApiProperty({ type: User })
  user!: User;
}

export class RefreshTokenDto {
  @ApiProperty()
  refreshToken!: string;
}

export class TokensDto {
  @ApiProperty()
  accessToken!: string;

  @ApiProperty()
  refreshToken!: string;
}
