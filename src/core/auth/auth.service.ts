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
import { AuthResponseDto, TokensDto } from './dto/auth-response.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signUp(body: SignUpDto): Promise<User> {
    const { username, email, password, confirmPassword } = body;

    this.validateConfirmPassword(password, confirmPassword);

    const hashedPassword = await this.hashPassword(password);

    try {
      const savedUser = await this.userRepository.createUser({
        username,
        email,
        password: hashedPassword,
      });

      if (!savedUser) {
        throw new InternalServerErrorException('Failed to create user');
      }

      return new User(savedUser);
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new BadRequestException('Username or email already exists');
      }
      throw new InternalServerErrorException(
        'An error occurred while creating the user',
      );
    }
  }

  async login(body: LoginDto): Promise<AuthResponseDto> {
    const { email, password } = body;

    const user = await this.userRepository.findByEmailOrThrow(email);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    await this.comparePasswords(password, user.password);

    const tokens = await this.generateTokens(user.id, user.email);

    await this.updateRefreshToken(user.id, tokens.refreshToken);

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

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('Access denied');
      }

      const isValid = await bcrypt.compare(refreshToken, user.refreshToken);

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
    await this.userRepository.updateUser(userId, {
      refreshToken: null,
    });
  }

  async getMe(userId: string): Promise<User> {
    const user = await this.userRepository.findByIdOrThrow(userId);

    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    return new User(user);
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

    await this.userRepository.updateUser(userId, {
      refreshToken: hashedRefreshToken,
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
