import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MongoDataSource} from '../datasources';
import {Role, UserCredential, UserCredentialRelations} from '../models';

export class UserCredentialRepository extends DefaultCrudRepository<
  UserCredential,
  typeof UserCredential.prototype.id,
  UserCredentialRelations
> {
  constructor(
    @inject('datasources.Mongo') dataSource: MongoDataSource,
  ) {
    super(UserCredential, dataSource);

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
}
