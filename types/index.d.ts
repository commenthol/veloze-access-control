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
export function authorize(defineAbilityFor: (payload: object) => Promise<PureAbility>, options?: {
    requestProperty: string;
}): Handler;
/**
 * @param {RawRule[]} rules
 * @returns {Handler}
 */
export function allow(rules: RawRule[]): Handler;
/**
 * check for CRUD permissions on subject
 * @param {string} subject
 * @returns {Handler}
 */
export function allowSubject(subject: string): Handler;
export function createAbilityBuilder(): AbilityBuilder<Ability>;
export type RawRule = import("@casl/ability").RawRule;
export type AbilityTuple = import("@casl/ability").AbilityTuple;
export type PureAbility = import("@casl/ability").PureAbility;
export type Handler = import("veloze").Handler;
import { AbilityBuilder } from '@casl/ability';
import { Ability } from '@casl/ability';
