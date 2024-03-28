import {BootMixin} from '@loopback/boot';
import {ApplicationConfig} from '@loopback/core';
import {
  RestExplorerBindings,
  RestExplorerComponent,
} from '@loopback/rest-explorer';
import {RepositoryMixin} from '@loopback/repository';
import {RestApplication} from '@loopback/rest';
import {ServiceMixin} from '@loopback/service-proxy';
import path from 'path';
import {MySequence} from './sequence';
import {PasswordHasherBindings} from './keys';
import {BcryptHarsher} from './services/hash.password.bcryptjs';
import {JWTAuthenticationStrategyBindings, TokenServiceConstants, UserServiceBindings} from './keys/jwt-key';
import {JWTService} from './services/jwt.service';
import {MyUserService} from './services/user.service';
import {MongoDataSource} from './datasources';
import {RefreshTokenRepository, UserCredentialRepository, UserRepository} from './repositories';
import {AuthenticationComponent} from '@loopback/authentication';

export {ApplicationConfig};
import {
  JWTAuthenticationComponent, RefreshTokenConstants, RefreshTokenServiceBindings, TokenServiceBindings,
} from '@loopback/authentication-jwt';
import {RefreshTokenService} from './services/refreshtoken.service';
export class AdminTemplateApplication extends BootMixin(
  ServiceMixin(RepositoryMixin(RestApplication)),
) {
  constructor(options: ApplicationConfig = {}) {
    super(options);

    // Set up the custom sequence
    this.sequence(MySequence);
    this.setupBindComponent();

    // Set up default home page
    this.static('/', path.join(__dirname, '../public'));

    // Customize @loopback/rest-explorer configuration here
    this.configure(RestExplorerBindings.COMPONENT).to({
      path: '/explorer',
    });
    this.component(RestExplorerComponent);

    this.projectRoot = __dirname;
    // Customize @loopback/boot Booter Conventions here
    this.bootOptions = {
      controllers: {
        // Customize ControllerBooter Conventions here
        dirs: ['controllers'],
        extensions: ['.controller.js'],
        nested: true,
      },
    };
  }

  setupBindComponent() :void  {
    this.component(AuthenticationComponent);
    this.component(JWTAuthenticationComponent);

    this.bind(PasswordHasherBindings.ROUNDS).to(10);
    this.bind(PasswordHasherBindings.PASSWORD_HASHER).toClass(BcryptHarsher);
    this.bind(JWTAuthenticationStrategyBindings.TOKEN_SERVICE).toClass(JWTService);
    this.bind(JWTAuthenticationStrategyBindings.TOKEN_SECRET).to(TokenServiceConstants.TOKEN_SECRET_VALUE,);
    this.bind(JWTAuthenticationStrategyBindings.TOKEN_EXPIRES_IN).to(TokenServiceConstants.TOKEN_EXPIRES_IN_VALUE);


    this.bind(UserServiceBindings.USER_SERVICE).toClass(MyUserService);
    this.dataSource(MongoDataSource, UserServiceBindings.DATASOURCE_NAME);
    this.bind(UserServiceBindings.USER_REPOSITORY).toClass(
      UserRepository,
    );
    this.bind(UserServiceBindings.USER_CREDENTIALS_REPOSITORY).toClass(
      UserCredentialRepository,
    );

    this.bind(RefreshTokenServiceBindings.REFRESH_TOKEN_SERVICE).toClass(
      RefreshTokenService,
    );
    this.bind(RefreshTokenServiceBindings.REFRESH_SECRET).to(
      RefreshTokenConstants.REFRESH_SECRET_VALUE,
    );
    this.bind(RefreshTokenServiceBindings.REFRESH_EXPIRES_IN).to(
      RefreshTokenConstants.REFRESH_EXPIRES_IN_VALUE,
    );
    this.bind(RefreshTokenServiceBindings.REFRESH_ISSUER).to(
      RefreshTokenConstants.REFRESH_ISSUER_VALUE,
    );
    this.bind(RefreshTokenServiceBindings.REFRESH_REPOSITORY).toClass(
      RefreshTokenRepository,
    );
  }
}
