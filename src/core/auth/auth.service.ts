import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { User } from 'src/modules/users/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { UserRepository } from 'src/modules/users/users.repository';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import {
  AuthResponse,
  SignUpResponse,
  TokensDto,
} from './dto/auth-response.dto';
import { MailService } from 'src/mail/mail.service';
import { AuthRepository } from './auth.repository';

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly authRepository: AuthRepository,
  ) {}

  async signUp(body: SignUpDto): Promise<SignUpResponse> {
    const { username, email, password, confirmPassword } = body;

    this.validateConfirmPassword(password, confirmPassword);

    const hashedPassword = await this.hashPassword(password);

    try {
      const savedUser = await this.userRepository.create({
        username,
        email,
        password: hashedPassword,
      });

      if (!savedUser) {
        throw new InternalServerErrorException('Failed to create user');
      }

      const otp = await this.generateOtp(savedUser.id);

      await this.mailService.sendConfirmationEmail({
        to: email,
        context: {
          username,
          otp,
        },
      });

      return {
        message: 'User created. Please verify your email with the OTP sent.',
        userId: savedUser.id,
      };
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new BadRequestException('Username or email already exists');
      }
      throw new InternalServerErrorException(
        'An error occurred while creating the user',
      );
    }
  }

  async verifyOtp(userId: string, otp: string): Promise<AuthResponse> {
    const otpRecord = await this.authRepository.findOtpByUserId(userId);

    if (!otpRecord || !otpRecord.otp) {
      throw new BadRequestException('OTP not found');
    }

    if (otpRecord.expires_at < new Date()) {
      throw new BadRequestException('OTP has expired');
    }

    const isValid = await bcrypt.compare(otp, otpRecord.otp);

    if (!isValid) {
      throw new BadRequestException('Invalid OTP');
    }

    await this.userRepository.update(userId, { is_verified: true });

    await this.authRepository.deleteOtpByUserId(userId);

    const user = await this.userRepository.findByIdOrThrow(userId);

    if (!user) {
      throw new InternalServerErrorException(
        'User not found after OTP verification',
      );
    }

    const tokens = await this.generateTokens(user.id, user.email);

    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      ...tokens,
      user: new User(user),
    };
  }

  async resendOtp(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findByIdOrThrow(userId);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.is_verified) {
      throw new BadRequestException('User is already verified');
    }

    const otp = await this.generateOtp(userId);

    await this.mailService.sendConfirmationEmail({
      to: user.email,
      context: {
        username: user.username,
        otp,
      },
    });

    return { message: 'OTP resent successfully' };
  }

  async login(body: LoginDto): Promise<AuthResponse> {
    const { email, password } = body;

    const user = await this.userRepository.findByEmailOrThrow(email);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const {
      id,
      email: userEmail,
      password: hashedPassword,
      is_verified,
    } = user;

    await this.comparePasswords(password, hashedPassword);

    this.checkUserVerification(is_verified);

    const tokens = await this.generateTokens(id, userEmail);

    await this.updateRefreshToken(id, tokens.refreshToken);

    return {
      ...tokens,
      user: new User(user),
    };
  }

  async refreshTokens(refreshToken: string): Promise<TokensDto> {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      const user = await this.userRepository.findByIdOrThrow(payload.sub);

      if (!user || !user.refresh_token) {
        throw new UnauthorizedException('Access denied');
      }

      const isValid = await bcrypt.compare(refreshToken, user.refresh_token);

      if (!isValid) {
        throw new UnauthorizedException('Access denied');
      }

      const tokens = await this.generateTokens(user.id, user.email);

      await this.updateRefreshToken(user.id, tokens.refreshToken);

      return tokens;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async logout(userId: string): Promise<void> {
    await this.userRepository.update(userId, {
      refresh_token: null,
    });
  }

  async getMe(userId: string): Promise<User> {
    const user = await this.userRepository.findByIdOrThrow(userId);

    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    return new User(user);
  }

  private async generateOtp(userId: string): Promise<string> {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const expiry = this.generateExpiryDate(5);

    const hashedOtp = await this.hashOtp(otp);

    await this.authRepository.createOtp(userId, hashedOtp, expiry);

    return otp;
  }

  private generateExpiryDate(minutes: number): Date {
    const expiry = new Date();
    expiry.setMinutes(expiry.getMinutes() + minutes);
    return expiry;
  }

  private async hashOtp(otp: string): Promise<string> {
    return bcrypt.hash(otp, 10);
  }

  private checkUserVerification(isVerified: boolean): void {
    if (!isVerified) {
      throw new UnauthorizedException(
        'Please verify your email before logging in',
      );
    }
  }

  private async generateTokens(
    userId: string,
    email: string,
  ): Promise<TokensDto> {
    const payload = { sub: userId, email };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  private async updateRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.userRepository.update(userId, {
      refresh_token: hashedRefreshToken,
    });
  }

  private validateConfirmPassword(
    password: string,
    confirmPassword: string,
  ): void {
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  private async comparePasswords(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<void> {
    const isValid = await bcrypt.compare(plainPassword, hashedPassword);

    if (!isValid) {
      throw new UnauthorizedException('Invalid email or password');
    }
  }
}
