'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const GE = require('@adonisjs/generic-exceptions')

/**
 * This exception is raised when user is not found. This usally
 * happens when trying to authenticate user using their
 * credentials.
 *
 * @class UserNotFoundException
 */
class UserNotFoundException extends GE.LogicalException {
  static invoke (message, uidField, passwordField, authScheme) {
    if (!uidField || !passwordField || !authScheme) {
      throw new Error('Cannot invoke exception without uidField, passwordField or authScheme')
    }

    const error = new this(message, 401, 'E_AUTH_INVALID')
    error.uidField = uidField
    error.passwordField = passwordField
    error.authScheme = authScheme
    return error
  }

  /**
   * Handle user not found exception, this method does all
   * lot of work to find the correct way to handle the
   * exception. Try reading the code to understand
   * it.
   *
   * @method handle
   *
   * @param  {Object} error
   * - `{ status: 500, uidField: 'id', passwordField: 'password', authScheme: 'session' }`
   * @param {Object} ctx
   *
   * @return {void}
   */
  async handle ({ status, uidField, passwordField, authScheme }, { request, response, session }) {
    const isJSON = request.accepts(['html', 'json']) === 'json'
    const errorMessages = [{ field: uidField, message: `Cannot find user with provided ${uidField}` }]

    /**
     * If request is json then return a json response
     */
    if (isJSON) {
      response.status(status).send(errorMessages)
      return
    }

    /**
     * If auth scheme is session, then flash the data
     * back to the form
     */
    if (authScheme === 'session') {
      session.withErrors(errorMessages).flashExcept([passwordField])
      await session.commit()
      response.redirect('back')
      return
    }

    /**
     * If using basic auth, then prompt user with a native
     * browser dialog
     */
    if (authScheme === 'basic') {
      response.header('WWW-Authenticate', 'Basic realm="example"')
      response.status(status).send('Access denied')
      return
    }

    /**
     * Fallback to json response
     */
    response.status(status).send(errorMessages)
  }
}

/**
 * This exception is raised when user password mis-matches. This usally
 * happens when trying to authenticate user using their credentials.
 *
 * @class PasswordMisMatchException
 */
class PasswordMisMatchException extends GE.LogicalException {
  static invoke (message, passwordField, authScheme) {
    if (!passwordField || !authScheme) {
      throw new Error('Cannot invoke exception without passwordField or authScheme')
    }
    const error = new this(message, 401, 'E_AUTH_INVALID')
    error.passwordField = passwordField
    error.authScheme = authScheme

    return error
  }

  /**
   * Handle password mis-match exception, this method does a
   * lot of work to find the correct way to handle the
   * exception. Try reading the code to understand
   * it.
   *
   * @method handle
   *
   * @param  {Object} error
   * - `{ status: 500, passwordField: 'password', authScheme: 'session' }`
   * @param {Object} ctx
   *
   * @return {void}
   */
  async handle ({ status, passwordField, authScheme }, { request, response, session }) {
    const isJSON = request.accepts(['html', 'json']) === 'json'
    const errorMessages = [{ field: passwordField, message: 'Invalid credential' }]

    /**
     * If request is json then return a json response
     */
    if (isJSON) {
      response.status(status).send(errorMessages)
      return
    }

    /**
     * If auth scheme is session, then flash the data
     * back to the form
     */
    if (authScheme === 'session') {
      session.withErrors(errorMessages).flashExcept([passwordField])
      await session.commit()
      response.redirect('back')
      return
    }

    /**
     * If using basic auth, then prompt user with a native
     * browser dialog
     */
    if (authScheme === 'basic') {
      response.header('WWW-Authenticate', 'Basic realm="example"')
      response.status(status).send('Access denied')
      return
    }

    /**
     * Fallback to json response
     */
    response.status(status).send(errorMessages)
  }
}

/**
 * This exception is raised when basic auth credentials are
 * missing.
 *
 * @class InvalidBasicAuthException
 */
class InvalidBasicAuthException extends GE.LogicalException {
  /**
   * The basic auth header/credentials are missing
   *
   * @method invoke
   *
   * @return {Object}
   */
  static invoke () {
    return new this('Cannot parse or read Basic auth header', 401, 'E_MISSING_AUTH_HEADER')
  }

  /**
   * Handle the exception itself
   *
   * @method handle
   *
   * @param  {Object} error
   * - `{ status: 500, passwordField: 'password', authScheme: 'session' }`
   * @param {Object} ctx
   *
   * @return {void}
   */
  handle ({ status }, { request, response }) {
    const isJSON = request.accepts(['html', 'json']) === 'json'

    if (!isJSON) {
      response.header('WWW-Authenticate', 'Basic realm="example"')
      response.status(status).send('Access denied')
      return
    }

    const error = [{ field: null, message: 'Basic auth header is missing' }]
    response.status(status).send(error)
  }
}

/**
 * This exception is raised when user session is invalid
 *
 * @class InvalidSessionException
 */
class InvalidSessionException extends GE.LogicalException {
  static invoke () {
    return new this('Invalid session', 401, 'E_AUTH_SESSION_INVALID')
  }
}

/**
 * This exception is raised when jwt token is invalid or
 * unable to find user for JWT token.
 *
 * @class InvalidJwtToken
 */
class InvalidJwtToken extends GE.LogicalException {
  static invoke (message) {
    return new this(message || 'The access token is missing or invalid', 401, 'E_AUTH_TOKEN_INVALID')
  }
}

/**
 * This exception is raised when jwt refresh token is
 * invalid.
 *
 * @class InvalidRefreshToken
 */
class InvalidRefreshToken extends GE.LogicalException {
  static invoke (refreshToken) {
    return new this("The refresh token is invalid", 401, 'E_AUTH_TOKEN_INVALID')
  }
}

/**
 * This exception is raised when jwt token is expired
 *
 * @class ExpiredJwtToken
 */
class ExpiredJwtToken extends GE.LogicalException {
  static invoke () {
    return new this('The access token has expired', 401, 'E_AUTH_TOKEN_INVALID')
  }
}

/**
 * This exception is raised when API token is invalid
 *
 * @class InvalidApiToken
 */
class InvalidApiToken extends GE.LogicalException {
  static invoke () {
    return new this('The access token is missing or invalid', 401, 'E_AUTH_TOKEN_INVALID')
  }
}

module.exports = {
  UserNotFoundException,
  PasswordMisMatchException,
  InvalidJwtToken,
  InvalidRefreshToken,
  ExpiredJwtToken,
  InvalidBasicAuthException,
  InvalidApiToken,
  InvalidSessionException
}
