/* eslint-disable @typescript-eslint/no-explicit-any */
import {inject, Getter} from '@loopback/core';
import {DefaultCrudRepository, repository, HasOneRepositoryFactory} from '@loopback/repository';
import {MongoDataSource} from '../datasources';
import {User, UserRelations, UserCredential, Role} from '../models';
import {UserCredentialRepository} from './user-credential.repository';

export class UserRepository extends DefaultCrudRepository<
  User,
  typeof User.prototype.id,
  UserRelations
> {

  public readonly userCredential: HasOneRepositoryFactory<UserCredential, typeof User.prototype.id>;

  constructor(
    @inject('datasources.Mongo') dataSource: MongoDataSource, @repository.getter('UserCredentialRepository') protected userCredentialRepositoryGetter: Getter<UserCredentialRepository>,
  ) {
    super(User, dataSource);
    this.userCredential = this.createHasOneRepositoryFactoryFor('userCredential', userCredentialRepositoryGetter);
    this.registerInclusionResolver('userCredential', this.userCredential.inclusionResolver);

    this.modelClass.observe('persist', async (ctx) => {
      ctx.data.modified = new Date();
    });
  }

  definePersistedModel(entityClass: typeof Role) {
    const modelClass = super.definePersistedModel(entityClass);
    modelClass.observe('after save', async (ctx, next) => {
      // logic after save
    })
    modelClass.observe('before save', async (ctx, next) => {
      // logic before save
    })
    modelClass.observe('after delete', async (ctx, next) => {
      // logic after delete
    })
    modelClass.observe('before delete', async (ctx, next) => {
      // logic before delete
    })
    return modelClass;
  }

  async findCredentials(
    userId: typeof User.prototype.id,
  ): Promise<UserCredential | undefined> {
    return this.userCredential(userId)
      .get()
      .catch(err => {
        if (err.code === 'ENTITY_NOT_FOUND') return undefined;
        throw err;
      });
  }

  async updateCredentials(
    userId: typeof User.prototype.id,
    password: string
  ): Promise<any | undefined> {
    return this.userCredential(userId).patch({
      password: password
    })
  }
}
