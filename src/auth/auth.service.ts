import { ConflictException, HttpException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt'
import { Tokens } from './types/tokens.type';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {

    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) { }

    async signTokens(userId: number, email: string): Promise<Tokens> {

        const [access_token, refresh_token] = await Promise.all([

            this.jwtService.signAsync(
                { id: userId, email },
                {
                    secret: this.configService.get('ACCESS_SECRET_KEY'),
                    expiresIn: 60 * 15
                }
            ),

            this.jwtService.signAsync(
                { id: userId, email },
                {
                    secret: this.configService.get('REFRESH_SECRET_KEY'),
                    expiresIn: 60 * 60 * 24 * 7
                }
            ),

        ])

        return { access_token: access_token, refresh_token: refresh_token }

    }

    async createHashRefreshToken(userId: number, refreshToken: string) {

        const hashRefreshToken = await bcrypt.hash(refreshToken, 10)

        await this.prisma.user.update({ where: { id: userId }, data: { hashRt: hashRefreshToken } })

    }

    async register(registerDto: RegisterDto): Promise<any> {

        const user = await this.prisma.user.findUnique({ where: { email: registerDto.email } })

        if (user) {
            throw new ConflictException('Email already exist')
        }

        const hashPassword = await bcrypt.hash(registerDto.hash, 10)

        const newUser = await this.prisma.user.create({ data: { ...registerDto, hash: hashPassword } })

        const { hash, hashRt, ...others } = newUser

        return others

    }



    async login(loginDto: LoginDto): Promise<Tokens> {

        const user = await this.prisma.user.findUnique({ where: { email: loginDto.email } })

        if (!user) {
            throw new NotFoundException('Email has been wrong')
        }

        const comparePassword = await bcrypt.compare(loginDto.hash, user.hash)

        if (!comparePassword) {
            throw new HttpException('Password has been wrong', HttpStatus.UNAUTHORIZED)
        }

        const tokens = await this.signTokens(user.id, user.email)

        await this.createHashRefreshToken(user.id, tokens.refresh_token)

        return tokens

    }

    async logout(userId: number): Promise<string> {

        await this.prisma.user.updateMany({ where: { id: userId, hashRt: { not: null } }, data: { hashRt: null } })

        return 'User has been logout'

    }

    async refreshTokens(userId: number, refreshToken: string) {

        const user = await this.prisma.user.findUnique({ where: { id: userId } })

        if (!user || !user.hashRt) {
            throw new HttpException('Access Denied', HttpStatus.FORBIDDEN)
        }

        const compareHashRefreshToken = await bcrypt.compare(refreshToken, user.hashRt)

        if (!compareHashRefreshToken) {
            throw new HttpException('Access Denied', HttpStatus.FORBIDDEN)
        }

        const tokens = await this.signTokens(user.id, user.email)

        await this.createHashRefreshToken(user.id, tokens.refresh_token)

        return tokens

    }

}
