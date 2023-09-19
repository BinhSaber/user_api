/**
 * Policy Mappings
 * (sails.config.policies)
 *
 * Policies are simple functions which run **before** your actions.
 *
 * For more information on configuring policies, check out:
 * https://sailsjs.com/docs/concepts/policies
 */

module.exports.policies = {

  /***************************************************************************
  *                                                                          *
  * Default policy for all controllers and actions, unless overridden.       *
  * (`true` allows public access)                                            *
  *                                                                          *
  ***************************************************************************/

  // '*': true,
  'UserController': {
    // By default, require requests to come from a logged-in user
    // (runs the policy in api/policies/isLoggedIn.js)
    '*': 'verifyToken',

    // Only allow admin users to delete other users
    // (runs the policy in api/policies/isAdmin.js)
    // 'delete': 'isAdmin',

    // Allow anyone to access the login action, even if they're not logged in.
    'login': 'can-login',
    'create': true,
    'refreshToken': true,
  }

};
