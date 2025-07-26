import { HttpError } from 'veloze'
import { Ability, AbilityBuilder, mongoQueryMatcher } from '@casl/ability'

/** @typedef {import('@casl/ability').RawRule} RawRule */
/** @typedef {import('@casl/ability').AbilityTuple} AbilityTuple */
/** @typedef {import('@casl/ability').PureAbility} PureAbility */
/** @typedef {import('veloze').Handler} Handler */

/**
 * @returns {AbilityBuilder<Ability>}
 */
export const createAbilityBuilder = () => {
  const builder = new AbilityBuilder(Ability)
  const { build } = builder
  builder.build = () => build({ conditionsMatcher: mongoQueryMatcher })
  // @ts-ignore
  return builder
}

/**
 * @param {(payload: object) => Promise<PureAbility>} defineAbilityFor
 * @param {{requestProperty: string}} [options]
 * @returns {Handler}
 * @example
 * import { Ability, AbilityBuilder, mongoQueryMatcher } from '@casl/ability'
 *
 * async function defineAbilityFor (jwtClaims) {
 *  const { can, cannot, build } = new AbilityBuilder(Ability)
 *  const { roles } = jwtClaims
 *  // from least to most privileges
 *  if (roles.includes('reader')) {
 *    can('read', 'Article')
 *    cannot('read', 'Article', { private: true })
 *  }
 *  if (roles.includes('admin')) {
 *    can('manage', 'all')
 *  }
 *  return build({ conditionsMatcher: mongoQueryMatcher })
 * }
 *
 * const router = new Router()
 * router.use(
 *  protect(...), // e.g. from `@veloze/jwt`
 *  authorize(defineAbilityFor)
 * )
 */
export function authorize(defineAbilityFor, options) {
  const { requestProperty = 'auth' } = options || {}
  if (typeof defineAbilityFor !== 'function') {
    throw new Error('defineAbilityFor must be a function')
  }
  return function authorizeHandler(req, _res, next) {
    if (!req.auth) {
      next(new HttpError(401))
      return
    }
    defineAbilityFor(req[requestProperty])
      .then((ability) => {
        req.ability = ability
        next()
      })
      .catch(next)
  }
}

/**
 * @param {RawRule[]} rules
 * @returns {Handler}
 */
export function allow(rules) {
  if (!rules?.length) {
    throw new Error('no rules defined')
  }
  rules.forEach(({ action, subject }, i) => {
    if (!action) {
      throw new Error(`action missing in rule ${i}`)
    } else if (!subject) {
      throw new Error(`subject missing in rule ${i}`)
    }
  })
  return function allowedHandler(req, _res, next) {
    for (const rule of rules) {
      const { action, subject, inverted } = rule
      const canCant = inverted ? 'cannot' : 'can'
      if (!req.ability?.[canCant](action, subject)) {
        throw new HttpError(403)
      }
    }
    next()
  }
}

const reqMethodActionMapper = {
  POST: 'create',
  PUT: 'update',
  PATCH: 'update',
  GET: 'read',
  DELETE: 'delete',
}
const getActionFromReqMethod = (method) => reqMethodActionMapper[method]

/**
 * check for CRUD permissions on subject
 * @param {string} subject
 * @returns {Handler}
 */
export function allowSubject(subject) {
  if (!subject) {
    throw new Error('subject is undefined')
  }
  return function allowedSubjectHandler(req, _res, next) {
    const action = getActionFromReqMethod(req.method)
    if (!action || !req.ability?.can(action, subject)) {
      next(new HttpError(403))
      return
    }
    next()
  }
}
