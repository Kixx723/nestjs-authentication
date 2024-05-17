import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signup(dto: AuthDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (existingUser) {
      throw new BadRequestException('Email already exist');
    }

    const password = await this.hashPassword(dto.password);

    await this.prisma.user.create({
      data: {
        email: dto.email,
        password: password,
      },
    });

    return { message: 'signup was successful' };
  }

  async signin(dto: AuthDto, req: Request, res: Response) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!existingUser) {
      throw new BadRequestException('Wrong Credentials');
    }

    const isPasswordMatch = await this.comparePassword(
      dto.password,
      existingUser.password,
    );

    if (!isPasswordMatch) {
      throw new BadRequestException('Wrong Credentials');
    }

    const token = await this.signToken(existingUser.id, existingUser.email);

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('token', token);

    return res.send({ message: 'Signed in succesfully', token: token });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'Logged out sucessfully' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePassword(password: string, hash: string) {
    return await bcrypt.compare(password, hash);
  }

  async signToken(id: string, email: string) {
    const payload = { id, email };
    return this.jwtService.signAsync(payload, {
      secret: process.env.JWT_SECRET,
    });
  }
}
