/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import '@japa/api-client'
import {
  GuardsList,
  ProvidersList,
  AuthManagerContract,
  GetProviderRealUser,
} from '@ioc:Adonis/Addons/Auth'

declare module '@japa/api-client' {
  export interface ApiRequest {
    /**
     * Auth manager reference
     */
    authManager: AuthManagerContract

    /**
     * Switch guard to login during the request
     */
    guard<K extends keyof GuardsList, Self>(
      this: Self,
      guard: K
    ): {
      /**
       * Login as a user
       */
      loginAs(...args: Parameters<GuardsList[K]['client']['login']>): Self
    }

    /**
     * Login as a user
     */
    loginAs(user: GetProviderRealUser<keyof ProvidersList>): this
  }
}
