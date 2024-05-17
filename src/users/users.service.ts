import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getUsers() {
    return await this.prisma.user.findMany({
      select: { id: true, email: true },
    });
  }

  async getUser(id: string, req: Request) {
    const user = await this.prisma.user.findUnique({ where: { id } });

    if (!user) {
      throw new NotFoundException();
    }
    const decodedUser = req.user as { id: string; email: string };
    
    if (user.id !== decodedUser.id) {
      throw new ForbiddenException();
    }
    delete user.password;
    return user;
  }
}
