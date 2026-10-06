/*
 *       .                             .o8                     oooo
 *    .o8                             "888                     `888
 *  .o888oo oooo d8b oooo  oooo   .oooo888   .ooooo.   .oooo.o  888  oooo
 *    888   `888""8P `888  `888  d88' `888  d88' `88b d88(  "8  888 .8P'
 *    888    888      888   888  888   888  888ooo888 `"Y88b.   888888.
 *    888 .  888      888   888  888   888  888    .o o.  )88b  888 `88b.
 *    "888" d888b     `V88V"V8P' `Y8bod88P" `Y8bod8P' 8""888P' o888o o888o
 *  ========================================================================
 *  Author:     Chris Brame
 *  Updated:    2/14/19 12:07 AM
 *  Copyright (c) 2014-2019. All rights reserved.
 */

module.exports = function (middleware, router, controllers) {
  // Shorten Vars
  const requireAuth = middleware.apiv2
  const apiV2Controllers = controllers.api.v2
  const isAdmin = middleware.isAdmin
  const isAgent = middleware.isAgent
  const isAgentOrAdmin = middleware.isAgentOrAdmin
  const hasPermission = middleware.canUser

  // Common
  router.post('/api/v2/login', controllers.api.v2.common.login)
  router.post('/api/v2/token', controllers.api.v2.common.token)

  // Accounts
  router.get('/api/v2/accounts', requireAuth, apiV2Controllers.accounts.get)
  router.post('/api/v2/accounts', requireAuth, apiV2Controllers.accounts.create)
  router.put('/api/v2/accounts/:username', requireAuth, apiV2Controllers.accounts.update)

  // Tickets
  router.get('/api/v2/tickets', requireAuth, apiV2Controllers.tickets.get)
  router.post('/api/v2/tickets', requireAuth, apiV2Controllers.tickets.create)
  router.post('/api/v2/tickets/transfer/:uid', requireAuth, isAdmin, apiV2Controllers.tickets.transferToThirdParty)
  router.get('/api/v2/tickets/:uid', requireAuth, apiV2Controllers.tickets.single)
  router.put('/api/v2/tickets/batch', requireAuth, apiV2Controllers.tickets.batchUpdate)
  router.put('/api/v2/tickets/:uid', requireAuth, apiV2Controllers.tickets.update)
  router.delete('/api/v2/tickets/:uid', requireAuth, apiV2Controllers.tickets.delete)
  router.delete('/api/v2/tickets/deleted/:id', requireAuth, isAdmin, apiV2Controllers.tickets.permDelete)

  // Groups
  router.get('/api/v2/groups', requireAuth, apiV2Controllers.groups.get)
  router.post('/api/v2/groups', requireAuth, apiV2Controllers.groups.create)
  router.put('/api/v2/groups/:id', requireAuth, apiV2Controllers.groups.update)
  router.delete('/api/v2/groups/:id', requireAuth, apiV2Controllers.groups.delete)

  // Teams
  router.get('/api/v2/teams', requireAuth, apiV2Controllers.teams.get)
  router.post('/api/v2/teams', requireAuth, apiV2Controllers.teams.create)
  router.put('/api/v2/teams/:id', requireAuth, apiV2Controllers.teams.update)
  router.delete('/api/v2/teams/:id', requireAuth, apiV2Controllers.teams.delete)

  // Departments
  router.get('/api/v2/departments', requireAuth, apiV2Controllers.departments.get)
  router.post('/api/v2/departments', requireAuth, apiV2Controllers.departments.create)
  router.put('/api/v2/departments/:id', requireAuth, apiV2Controllers.departments.update)
  router.delete('/api/v2/departments/:id', requireAuth, apiV2Controllers.departments.delete)

  // Notices
  router.get('/api/v2/notices', requireAuth, apiV2Controllers.notices.get)
  router.put('/api/v2/notices/:id', requireAuth, hasPermission('notices:update'), apiV2Controllers.notices.update)
  router.put('/api/v2/notices/:id/activate', requireAuth, hasPermission('notices:activate'), apiV2Controllers.notices.activate)
  router.get('/api/v2/notices/clear', requireAuth, hasPermission('notices:deactivate'), apiV2Controllers.notices.clear)
  router.delete('/api/v2/notices/:id', requireAuth, hasPermission('notices:delete'), apiV2Controllers.notices.delete)

  // ElasticSearch
  router.get('/api/v2/es/search', middleware.api, apiV2Controllers.elasticsearch.search)
  router.get('/api/v2/es/rebuild', requireAuth, isAdmin, apiV2Controllers.elasticsearch.rebuild)
  router.get('/api/v2/es/status', requireAuth, isAdmin, apiV2Controllers.elasticsearch.status)

  router.get('/api/v2/mailer/check', requireAuth, isAdmin, apiV2Controllers.mailer.check)
}
