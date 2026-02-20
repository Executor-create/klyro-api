import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { User } from 'src/modules/users/entities/user.entity';
import { AuthService } from './auth.service';
import { ApiResponse } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  @ApiResponse({
    status: 201,
    description: 'The user has been successfully created.',
    type: User,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request. The request body is invalid.',
  })
  async signUp(@Body() body: SignUpDto): Promise<User> {
    const newUser = await this.authService.signUp(body);
    return newUser;
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    status: 200,
    description: 'The user has been successfully authenticated.',
    type: User,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request. The request body is invalid.',
  })
  async login(@Body() body: LoginDto): Promise<User> {
    return await this.authService.login(body);
  }
}
