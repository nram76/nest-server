import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from '../utils/constants';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async signup(dto: AuthDto) {
    const { email, password} = dto;

    const founduser = await this.prisma.user.findUnique({ where: { email } });

    if (founduser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
        data: {
            email,
            hashedPassword
        }
    })

    return { message: 'singup was successfull' };
  }
  async signin(dto: AuthDto, req: Request, res: Response) {
    const { email, password } = dto;

    const founduser = await this.prisma.user.findUnique({ where: { email } });

    if (!founduser) {
      throw new BadRequestException('Wrong credentials');
    }

    const isMatch = await this.comparePasswords({
      password,
      hash: founduser.hashedPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Wrong credentials');
    }

    // sign jwt and return to the user

    const token = await this.signToken({
      id: founduser.id,
      email: founduser.email,
    });

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('token', token);

    return res.send({ message: 'Logged in successfully' });
  }
  async signout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'Logged out successfully' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;

    const hashedPassword = await bcrypt.hash(password, saltOrRounds);

    return hashedPassword;
  }

  async comparePasswords(args: { password: string; hash: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }

  async signToken(args: { id: string; email: string; }) {
    const payload = args;

    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }

  async homeCheck(){
    try{
      return 'home reached!'
    } catch (error) {
      return error;
    }
  }
}
