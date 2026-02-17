import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { User } from 'src/modules/users/entities/user.entity';
import { AuthService } from './auth.service';
import { ApiResponse } from '@nestjs/swagger';

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
}
