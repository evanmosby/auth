/*
 * @adonisjs/auth
 *
 * (c) AdonisJS Auth
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { AuthManagerContract } from '@ioc:Adonis/Addons/Auth'
import { ContainerBindings } from '@ioc:Adonis/Core/Application'

/**
 * Define test bindings
 */
export function defineTestsBindings(
  ApiRequest: ContainerBindings['Japa/Preset/ApiRequest'],
  ApiClient: ContainerBindings['Japa/Preset/ApiClient'],
  AuthManager: AuthManagerContract
) {
  /**
   * Set "sessionClient" on the api request
   */
  ApiRequest.getter(
    'authManager',
    function () {
      return AuthManager
    },
    true
  )

  /**
   * Login user using the default guard
   */
  ApiRequest.macro('loginAs', function (user) {
    this['authData'] = {
      client: this.authManager.client(this.authManager.defaultGuard),
      args: [user],
    }

    return this
  })

  /**
   * Login user using a custom guard
   */
  ApiRequest.macro('guard', function (mapping) {
    return {
      loginAs: (...args: any[]) => {
        this['authData'] = {
          client: this.authManager.client(mapping),
          args,
        }
        return this
      },
    }
  })

  /**
   * Hook into the request and login the user
   */
  ApiClient.setup(async (request) => {
    const authData = request['authData']
    if (!authData) {
      return
    }

    const requestData = await authData.client.login(...authData.args)

    if (requestData.headers) {
      request.headers(requestData.headers)
    }
    if (requestData.session) {
      request.session(requestData.session)
    }
    if (requestData.cookies) {
      request.cookies(requestData.cookies)
    }

    return async () => {
      await authData.client.logout(...authData.args)
    }
  })
}
