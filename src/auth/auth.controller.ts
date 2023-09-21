import { Body, Controller, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenGuard } from './guard/refresh-token.guard';
import { GetCurrentUser } from './decorator/get-current-user.decorator';
import { GetCurrentUserById } from './decorator/get-current-user-by-id.decorator';
import { Public } from './decorator/public.decorator';

@Controller('auth')
export class AuthController {

    constructor(private readonly authService: AuthService) { }

    @Public()
    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    register(@Body() registerDto: RegisterDto) {

        return this.authService.register(registerDto)

    }

    @Public()
    @Post('login')
    @HttpCode(HttpStatus.OK)
    login(@Body() loginDto: LoginDto) {

        return this.authService.login(loginDto)

    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    logout(@GetCurrentUserById() userId: number) {

        return this.authService.logout(userId)

    }

    @Public()
    @UseGuards(RefreshTokenGuard)
    @Post('refresh')
    refreshTokens(@GetCurrentUserById() userId: number, @GetCurrentUser('refreshToken') refreshToken: string) {


        return this.authService.refreshTokens(userId, refreshToken)

    }

}
