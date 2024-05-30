import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { Request } from 'express';
import { AtGuard, RtGuard } from 'src/common/guards';
import {
  GetCurrentUser,
  GetCurrentUserId,
  Public,
} from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }

  @Post('signin')
  @Public()
  @HttpCode(HttpStatus.OK)
  signIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signIn(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  @Post('refresh')
  @Public() // its guarded as public first, so ATGuar should pass it
  @UseGuards(RtGuard) // then using refresh token guard
  @HttpCode(HttpStatus.OK)
  refreshToken(
    @GetCurrentUser('refreshToken') rt: string,
    @GetCurrentUserId() userId: number,
  ): Promise<Tokens> {
    return this.authService.refreshToken(userId, rt);
  }
}
