import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { User } from 'src/modules/users/entities/user.entity';
import { AuthService } from './auth.service';
import { ApiResponse, ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from 'src/shared/guards/auth.guard';
import {
  AuthResponse,
  RefreshTokenDto,
  SignUpResponse,
  TokensDto,
} from './dto/auth-response.dto';
import { UserId } from 'src/shared/decorators/user.decorator';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  @ApiResponse({
    status: 201,
    description: 'User successfully created',
    type: SignUpResponse,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request',
  })
  async signUp(@Body() body: SignUpDto): Promise<SignUpResponse> {
    return this.authService.signUp(body);
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'OTP verified successfully',
    type: AuthResponse,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid OTP or OTP expired',
  })
  @Post('verify-otp')
  async verifyOtp(@Body() body: VerifyOtpDto): Promise<AuthResponse> {
    return this.authService.verifyOtp(body.userId, body.otp);
  }

  @Post('resend-otp')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'OTP resent successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request',
  })
  async resendOtp(@Body() body: ResendOtpDto): Promise<{ message: string }> {
    return this.authService.resendOtp(body.userId);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'User successfully authenticated',
    type: AuthResponse,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  async login(@Body() body: LoginDto): Promise<AuthResponse> {
    return this.authService.login(body);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'Tokens refreshed successfully',
    type: TokensDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired refresh token',
  })
  async refresh(@Body() body: RefreshTokenDto): Promise<TokensDto> {
    return this.authService.refreshTokens(body.refreshToken);
  }

  @UseGuards(AuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'Returns authenticated user',
    type: User,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  async getMe(@UserId() userId: string): Promise<User> {
    return this.authService.getMe(userId);
  }

  @UseGuards(AuthGuard)
  @Post('logout')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'User successfully logged out',
  })
  async logout(@UserId() userId: string): Promise<{ message: string }> {
    await this.authService.logout(userId);
    return { message: 'Successfully logged out' };
  }
}
