/* eslint-disable @typescript-eslint/no-explicit-any */
// Copyright IBM Corp. and LoopBack contributors 2020. All Rights Reserved.
// Node module: @loopback/example-todo-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {authenticate} from '@loopback/authentication';
import {
  RefreshTokenServiceBindings,
  TokenObject,
  TokenServiceBindings,
  UserServiceBindings,
} from '@loopback/authentication-jwt';
import {inject, intercept} from '@loopback/core';
import {model, property, repository} from '@loopback/repository';
import isemail from 'isemail';
import {
  get,
  getModelSchemaRef,
  HttpErrors,
  post, put,
  requestBody,
  RequestWithSession,
  response,
  Response,
  RestBindings,
  SchemaObject,
} from '@loopback/rest';
import {SecurityBindings, securityId, UserProfile} from '@loopback/security';
import _ from 'lodash';
import {RoleRepository, UserRepository} from '../repositories';
import {KeyAndPassword, ResetPasswordInit, User} from '../models';
import {RefreshTokenService} from '../services/refreshtoken.service';
import {JWTService} from '../services/jwt.service';
// import {authorize} from '@loopback/authorization';
// import {basicAuthorization} from '../services/basic.authorizor';
import createError from 'http-errors';
import {MyUserService} from '../services/user.service';
import {Credentials, PasswordHasherBindings} from '../keys';
import {PasswordHashes} from '../services/hash.password.bcryptjs';
import {logError} from '../interceptors';
import {SentMessageInfo} from 'nodemailer';
import {validateKeyPassword} from '../services/validator';

type RefreshGrant = {
  refreshToken: string;
};

// Describes the schema of grant object
const RefreshGrantSchema: SchemaObject = {
  type: 'object',
  required: ['refreshToken'],
  properties: {
    refreshToken: {
      type: 'string',
    },
  },
};

// Describes the request body of grant object
const RefreshGrantRequestBody = {
  description: 'Reissuing Access Token',
  required: true,
  content: {
    'application/json': {schema: RefreshGrantSchema},
  },
};

@model()
export class NewUserRequest extends User {
  @property({
    type: 'string',
    required: true,
  })
  password: string;
  @property({
    type: 'string',
  })
  roleName?: string;
}

const CredentialsSchema: SchemaObject = {
  type: 'object',
  required: ['username', 'password'],
  properties: {
    username: {
      type: 'string',
    },
    password: {
      type: 'string',
      minLength: 8,
    },
    rememberMe: {
      type: 'boolean',
    },
  },
};

export const CredentialsRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': {schema: CredentialsSchema},
  },
};

@intercept(logError)
export class UserController {
  constructor(
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(SecurityBindings.USER, {optional: true})
    public user: UserProfile,
    @repository(UserRepository) protected userRepository: UserRepository,
    @repository(RoleRepository) protected roleRepository: RoleRepository,
    // @repository(PersonalTokenRepository) protected personalTokenRepository: PersonalTokenRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER) public passwordHarshes: PasswordHashes,
    @inject(RefreshTokenServiceBindings.REFRESH_TOKEN_SERVICE)
    public refreshService: RefreshTokenService,
    @inject(RestBindings.Http.REQUEST) private req: RequestWithSession,
    @inject(RestBindings.Http.RESPONSE) private res: Response,
  ) {
  }

  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<{accessToken: string}> {
    // ensure the user exists, and the password is correct
    const user = await this.userService.verifyCredentials(credentials);

    // convert a User object into a UserProfile object (reduced set of properties)
    const userProfile = this.userService.convertToUserProfile(user);

    // create a JSON Web Token based on the user profile
    const accessToken = await this.jwtService.generateToken(userProfile);
    if (credentials.rememberMe) {
      return this.refreshService.generateToken(
        userProfile,
        accessToken,
      );
    }
    return {accessToken};
  }

  @authenticate('jwt')
  // @authenticate({
  //   strategy: 'jwt',
  // })
  @get('/whoAmI', {
    responses: {
      '200': {
        description: 'Return current user',
        content: {
          'application/json': {
            schema: {
              type: 'string',
            },
          },
        },
      },
    },
  })
  async whoAmI(
    @inject(SecurityBindings.USER)
      currentUserProfile: UserProfile,
  ): Promise<string> {
    return currentUserProfile[securityId];
  }

  @post('/users/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': User,
            },
          },
        },
      },
    },
  })
  async signUp(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(NewUserRequest, {
            title: 'NewUser',
          }),
        },
      },
    })
      newUserRequest: any,
  ): Promise<User> {
    try {
      const findUser = await this.userRepository.find({
        where: {or: [{username: newUserRequest.username}, {email: newUserRequest.email}]},
      });

      if (findUser && findUser.length > 0) {
        throw createError(422, 'username or email exist');
      }
      const password = await this.passwordHarshes.hashPassword(newUserRequest.password);
      delete (newUserRequest as Partial<NewUserRequest>).password;
      let roleDefault;
      if (newUserRequest.roleName) {
        roleDefault = await this.roleRepository.findOne({
          where: {name: newUserRequest.roleName},
        });
      } else {
        roleDefault = await this.roleRepository.findOne({
          where: {name: 'user'},
        });
      }
      delete (newUserRequest as Partial<NewUserRequest>).roleName;

      newUserRequest.roleId = roleDefault?.id;

      const savedUser = await this.userRepository.create(
        _.omit(newUserRequest, 'password'),
      );


      await this.userRepository.userCredential(savedUser.id).create({password});

      return savedUser;
    } catch (error) {
      throw createError(422, error);
    }
  }

  @post('/refresh', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                accessToken: {
                  type: 'object',
                },
              },
            },
          },
        },
      },
    },
  })
  async refresh(
    @requestBody(RefreshGrantRequestBody) refreshGrant: RefreshGrant,
  ): Promise<TokenObject> {
    return this.refreshService.refreshToken(refreshGrant.refreshToken);
  }


  @authenticate({
    strategy: 'jwt',
  })
  @get('/me')
  @response(200, {
    description: 'User model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(User, {includeRelations: true}),
      },
    },
  })
  async findMe(): Promise<any> {
    const user: any = await this.userService.findMe(this.req);
    const data: any = {};
    data.id = user.id;
    data.username = user.username;
    data.email = user.email;
    data.role = user.role;
    return data;
  }


  @authenticate({
    strategy: 'jwt',
  })
  @post('/users/logout', {
    responses: {
      '200': {
        description: 'Message',
      },
    },
  })
  async logout(): Promise<any> {
    const bearerToken = this.req.headers?.authorization ?? '';

    if (bearerToken) {
      const tokenArray = bearerToken.split(' ');
      await this.jwtService.revokeToken(tokenArray[1]);
      return 'Ok';
    }
    if (this.req.session) {
      this.req.session.destroy();
    }
    throw new HttpErrors.Unauthorized(
      `Error revoke token : 'token' is invalid`,
    );
  }

  @authenticate({
    strategy: 'jwt',
  })
  @post('/change-password', {
    responses: {
      '200': {},
    },
  })
  async changePassword(
    @requestBody({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            properties: {
              oldPassword: {
                type: 'string',
              },
              newPassword: {
                type: 'string',
              },
              reNewPassword: {
                type: 'string',
              },
            },
          },
        },
      },
    })
      body: any,
  ): Promise<any> {
    const invalidCredentialsError = 'Invalid password.';

    const user: any = await this.userService.findMe(this.req);
    const credentialsFound = await this.userRepository.findCredentials(
      user.id,
    );
    if (!credentialsFound) {
      throw new HttpErrors.Unauthorized(invalidCredentialsError);
    }

    const passwordMatched = await this.passwordHarshes.comparePassword(
      body.oldPassword,
      credentialsFound.password,
    );

    if (!passwordMatched) {
      throw new HttpErrors.Unauthorized(invalidCredentialsError);
    }
    if (body.newPassword !== body.reNewPassword) {
      throw new HttpErrors.Unauthorized('Re-enter password do Not match!');
    }
    const password = await this.passwordHarshes.hashPassword(body.newPassword);

    await this.userRepository.updateCredentials(user.id, password);
    await this.refreshService.revokeAllToken(user.id);
    await this.jwtService.revokeAllToken(this.req);
    return 'Update password success';
  }


  @post('/users/reset-password/init', {
    responses: {
      '200': {
        description: 'Confirmation that reset password email has been sent',
      },
    },
  })
  async resetPasswordInit(
    @requestBody() resetPasswordInit: ResetPasswordInit,
  ): Promise<string> {
    if (!isemail.validate(resetPasswordInit.email)) {
      throw new HttpErrors.UnprocessableEntity('Invalid email address');
    }

    const sentMessageInfo: SentMessageInfo =
      await this.userService.requestPasswordReset(
        resetPasswordInit.email,
      );

    if (sentMessageInfo.accepted.length) {
      return 'Successfully sent reset password link';
    }
    throw new HttpErrors.InternalServerError(
      'Error sending reset password email',
    );
  }


  @put('/users/reset-password/finish', {
    responses: {
      '200': {
        description: 'A successful password reset response',
      },
    },
  })
  async resetPasswordFinish(
    @requestBody() keyAndPassword: KeyAndPassword,
  ): Promise<string> {
    validateKeyPassword(keyAndPassword);

    const foundUser = await this.userRepository.findOne({
      where: {resetKey: keyAndPassword.resetKey},
    });

    if (!foundUser) {
      throw new HttpErrors.NotFound(
        'No associated account for the provided reset key',
      );
    }

    const user = await this.userService.validateResetKeyLifeSpan(
      foundUser,
    );

    const password = await this.passwordHarshes.hashPassword(
      keyAndPassword.password,
    );

    try {
      await this.userRepository.updateCredentials(user.id, password);
      await this.userRepository.updateById(user.id, user);
    } catch (e) {
      return e;
    }

    return 'Password reset successful';
  }
}