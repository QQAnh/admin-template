import {
  Application, CoreBindings, inject,
  /* inject, Application, CoreBindings, */
  lifeCycleObserver, // The decorator
  LifeCycleObserver, // The interface
} from '@loopback/core';
import {repository} from '@loopback/repository';
import {RoleRepository} from '../repositories';
import {Role} from '../models';

/**
 * This class will be bound to the application as a `LifeCycleObserver` during
 * `boot`
 */
@lifeCycleObserver('')
export class AddDataObserver implements LifeCycleObserver {

  constructor(
    @inject(CoreBindings.APPLICATION_INSTANCE) private app: Application,
    @repository(RoleRepository) protected roleRepository : RoleRepository,

  ) {}


  /**
   * This method will be invoked when the application initializes. It will be
   * called at most once for a given application instance.
   */
  async init(): Promise<void> {
    // Add your logic for init
  }

  /**
   * This method will be invoked when the application starts.
   */
  async start(): Promise<void> {
    const countRole = (await this.roleRepository.count()).count;
    let roleData: Role;
    const roles = [
      'user',
      'admin',
    ];
    if (countRole === 0) {
      for (const role of roles) {
        roleData = new Role({
          description: '',
          name: role,
        });
        await this.roleRepository.create(roleData);
      }
    }
    // Add your logic for start
  }

  /**
   * This method will be invoked when the application stops.
   */
  async stop(): Promise<void> {
    // Add your logic for stop
  }
}
