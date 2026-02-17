import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { User } from 'src/modules/users/entities/user.entity';
import { AuthRepository } from './auth.repository';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private readonly authRepository: AuthRepository) {}

  async signUp(body: SignUpDto): Promise<User> {
    const { username, email, password, confirmPassword } = body;

    this.validateConfirmPassword(password, confirmPassword);

    const hashedPassword = await this.hashPassword(password);

    try {
      const savedUser = await this.authRepository.createUser({
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
}
