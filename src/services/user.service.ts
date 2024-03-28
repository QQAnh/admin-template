import {User, UserWithRelations} from '../models';
import {Credentials, PasswordHasherBindings} from '../keys';
import {repository} from '@loopback/repository';
import {RoleRepository, UserRepository} from '../repositories';
import {HttpErrors, RequestWithSession} from '@loopback/rest';
import {securityId, UserProfile} from '@loopback/security';
import {inject} from '@loopback/core';
import {PasswordHashes} from './hash.password.bcryptjs';
import {UserService} from '@loopback/authentication';
import {JWTService} from './jwt.service';
import {TokenServiceBindings} from '@loopback/authentication-jwt';
import {SentMessageInfo} from 'nodemailer';
import {subtractDates} from '../actions';
import {v4 as uuidv4} from 'uuid';
import {EmailService} from './email.service';

export class MyUserService implements UserService<User, Credentials> {
  constructor(
    @repository(UserRepository) public userRepository: UserRepository,
    @repository(RoleRepository) public roleRepository: RoleRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER) public passwordHarshes: PasswordHashes,
    @inject(TokenServiceBindings.TOKEN_SERVICE) public jwtService: JWTService,
    @inject('services.EmailService') public emailService: EmailService,
  ) {}

  async verifyCredentials(credentials: Credentials): Promise<User>{
    const invalidCredentialsError = 'Invalid email or password.';
    const foundUser = await this.userRepository.findOne({
      where: {username: credentials.username}
    });
    if (!foundUser) {
      throw new HttpErrors.Unauthorized(invalidCredentialsError);
    }
    const credentialsFound = await this.userRepository.findCredentials(
      foundUser.id,
    );
    if (!credentialsFound) {
      throw new HttpErrors.Unauthorized(invalidCredentialsError);
    }
    const passwordMatched = await this.passwordHarshes.comparePassword(
      credentials.password,
      credentialsFound.password,
    );

    if (!passwordMatched) {
      throw new HttpErrors.Unauthorized(invalidCredentialsError);
    }
    const roleUser = await this.roleRepository.findById(foundUser?.roleId);
    foundUser.role = roleUser.name;
    delete foundUser['roleId']
    return foundUser;
  }

  convertToUserProfile(user: User): UserProfile {
    return {
      [securityId]: user.id!.toString(),
      name: user.username,
      id: user.id,
      email: user.email,
      role: user.role,
    };
  }
  async findUserById(id: string): Promise<User & UserWithRelations> {
    const userNotfound = 'invalid User';
    const foundUser = await this.userRepository.findOne({
      where: {id: id},
      fields: ['id', 'username', 'email', 'roleId']
    });

    if (!foundUser) {
      throw new HttpErrors.Unauthorized(userNotfound);
    }
    const roleUser = await this.roleRepository.findById(foundUser?.roleId);
    if (!roleUser){
      throw new HttpErrors.Unauthorized('invalid Role');
    }
    foundUser.role = roleUser.name;
    delete foundUser['roleId']
    return foundUser;
  }

  async findMe(req: RequestWithSession): Promise<User> {
    const token = this.jwtService.extractCredentials(req);


    const userProfile: UserProfile = await this.jwtService.verifyToken(token);
    const user = await this.findUserById(userProfile.id)
    return user;
  }

  async requestPasswordReset(email: string): Promise<SentMessageInfo> {
    const noAccountFoundError =
      'No account associated with the provided email address.';
    const foundUser = await this.userRepository.findOne({
      where: {email},
    });

    if (!foundUser) {
      throw new HttpErrors.NotFound(noAccountFoundError);
    }

    const user = await this.updateResetRequestLimit(foundUser);

    try {
      await this.userRepository.updateById(user.id, user);
    } catch (e) {
      return e;
    }
    return this.emailService.sendResetPasswordMail(user);
  }

  async updateResetRequestLimit(user: User): Promise<User> {
    const resetTimestampDate = new Date(user.resetTimestamp);

    const difference = await subtractDates(resetTimestampDate);

    if (difference === 0) {
      user.resetCount = user.resetCount + 1;

      if (user.resetCount > +(process.env.PASSWORD_RESET_EMAIL_LIMIT ?? 2)) {
        throw new HttpErrors.TooManyRequests(
          'Account has reached daily limit for sending password-reset requests',
        );
      }
    } else {
      user.resetTimestamp = new Date().toLocaleDateString();
      user.resetCount = 1;
    }
    // For generating unique reset key there are other options besides the proposed solution below.
    // Feel free to use whatever option works best for your needs
    user.resetKey = uuidv4();
    user.resetKeyTimestamp = new Date().toLocaleDateString();

    return user;
  }

  async validateResetKeyLifeSpan(user: User): Promise<User> {
    const resetKeyLifeSpan = new Date(user.resetKeyTimestamp);
    const difference = await subtractDates(resetKeyLifeSpan);

    user.resetKey = '';
    user.resetKeyTimestamp = '';

    if (difference !== 0) {
      throw new HttpErrors.BadRequest('The provided reset key has expired.');
    }

    return user;
  }
}