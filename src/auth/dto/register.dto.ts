import { IsNotEmpty, IsEmail } from 'class-validator'

export class RegisterDto {

    @IsNotEmpty()
    @IsEmail()
    email: string

    @IsNotEmpty()
    hash: string

}