import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { User } from 'src/modules/users/entities/user.entity';
import { AuthRepository } from './auth.repository';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { UserRepository } from 'src/modules/users/users.repository';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly userRepository: UserRepository,
    private readonly jwtService: JwtService,
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

      console.log('Error creating user:', error);

      throw new InternalServerErrorException(
        'An error occurred while creating the user',
      );
    }
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
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  }

  async login(body: LoginDto): Promise<User> {
    const { email, password } = body;

    const user = await this.userRepository.findByEmailOrThrow(email);

    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    await this.comparePasswords(password, user.password);

    const token = await this.generateToken(user.id, user.email);

    const updatedUser = await this.authRepository.updateUserToken(
      user.id,
      token,
    );

    if (!updatedUser) {
      throw new InternalServerErrorException('Failed to update user token');
    }

    return new User(updatedUser);
  }

  private async comparePasswords(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    const isValid = await bcrypt.compare(plainPassword, hashedPassword);

    if (!isValid) {
      throw new BadRequestException('Invalid email or password');
    }

    return isValid;
  }

  private async generateToken(userId: string, email: string): Promise<string> {
    const payload = { sub: userId, email };
    const token = await this.jwtService.signAsync(payload);

    if (!token) {
      throw new InternalServerErrorException('Failed to generate token');
    }

    return token;
  }
}
