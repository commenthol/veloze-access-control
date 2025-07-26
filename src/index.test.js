import assert from 'node:assert'
import { describe, it, before } from 'mocha'
import { authorize, allow, allowSubject, createAbilityBuilder } from '#index.js'
import { HttpError, connect } from 'veloze'

describe('access-control', function () {
  let defineAbilityFor
  before(function () {
    defineAbilityFor = async (roles = []) => {
      const { can, cannot, build } = createAbilityBuilder()
      // from least to most privileges
      if (roles.includes('reader')) {
        can('read', 'Article')
        cannot('read', 'Article', { private: true })
      }
      if (roles.includes('admin')) {
        can('manage', 'all')
      }
      return build()
    }
  })

  describe('authorize', function () {
    it('shall throw if defineAbilityFor is bad', function () {
      assert.throws(() => {
        // @ts-expect-error
        authorize('hi')
      }, new Error('defineAbilityFor must be a function'))
    })

    it('shall add req.ability', function (done) {
      const req = { auth: [] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err, undefined)
          assert.equal(req.ability.constructor.name, 'Ability')
          done()
        } catch (e) {
          done(e)
        }
      }
      // @ts-ignore
      authorize(defineAbilityFor)(req, res, next)
    })

    it('shall fail with 401 when req.auth is not defined', function (done) {
      const req = {}
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err?.message, 'Unauthorized')
          done()
        } catch (e) {
          done(e)
        }
      }
      connect(
        authorize(defineAbilityFor),
        allow([{ action: 'create', subject: 'Article' }]),
        // @ts-ignore
      )(req, res, next)
    })
  })

  describe('allow', function () {
    it('shall throw', function () {
      assert.throws(() => {
        allow([])
      }, new Error('no rules defined'))
    })

    it('shall throw with undefined action', function () {
      assert.throws(() => {
        // @ts-ignore
        allow([{ subject: 'Article' }])
      }, new Error('action missing in rule 0'))
    })

    it('shall throw with undefined subject', function () {
      assert.throws(() => {
        // @ts-ignore
        allow([{ action: 'read' }])
      }, new Error('subject missing in rule 0'))
    })

    it('shall pass admin', function (done) {
      const req = { auth: ['admin'] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err, undefined)
          done()
        } catch (e) {
          done(e)
        }
      }
      connect(
        authorize(defineAbilityFor),
        allow([{ action: 'create', subject: 'Article' }]),
        // @ts-ignore
      )(req, res, next)
    })

    it('shall reject reader', function (done) {
      const req = { auth: ['reader'] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err.message, 'Forbidden')
          done()
        } catch (e) {
          done(e)
        }
      }
      connect(
        authorize(defineAbilityFor),
        allow([{ action: 'create', subject: 'Article' }]),
        // @ts-ignore
      )(req, res, next)
    })

    it('shall pass reader', function (done) {
      const req = { auth: ['reader'] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err?.message, undefined)
          done()
        } catch (e) {
          done(e)
        }
      }
      connect(
        authorize(defineAbilityFor),
        allow([{ action: 'read', subject: 'Article' }]),
        // @ts-ignore
      )(req, res, next)
    })

    it('shall reject reader when Article is private', function (done) {
      const req = { auth: ['reader'] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err?.message, 'Forbidden')
          done()
        } catch (e) {
          done(e)
        }
      }
      connect(
        authorize(defineAbilityFor),
        allow([{ action: 'read', subject: 'Article' }]),
        (req, res, next) => {
          class Article {
            private = true
          }
          const article = new Article()
          if (
            !req.ability?.can(
              'read',
              article,
              JSON.stringify({ private: true }),
            )
          ) {
            next(new HttpError(403))
            return
          }
          next()
        },
        // @ts-ignore
      )(req, res, next)
    })

    it('shall reject anon', function (done) {
      const req = { auth: [] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err.message, 'Forbidden')
          done()
        } catch (e) {
          done(e)
        }
      }
      connect(
        authorize(defineAbilityFor),
        allow([{ action: 'create', subject: 'Article' }]),
        // @ts-ignore
      )(req, res, next)
    })
  })

  describe('allowSubject', function () {
    let mws
    before(function () {
      mws = connect(
        authorize(defineAbilityFor),
        allowSubject('Article'),
        (req, res, next) => {
          res.text = req.method
          next()
        },
      )
    })

    it('shall throw with undefined subject', function () {
      assert.throws(() => {
        // @ts-ignore
        allowSubject()
      }, new Error('subject is undefined'))
    })

    it('shall pass admin', function (done) {
      const req = { method: 'DELETE', auth: ['admin'] }
      const res = {}
      const next = (err) => {
        try {
          assert.ok(!err)
          assert.equal(res.text, req.method)
          done()
        } catch (e) {
          done(e)
        }
      }
      mws(req, res, next)
    })

    it('shall reject anonymous', function (done) {
      const req = { method: 'DELETE', auth: [] }
      const res = {}
      const next = (err) => {
        try {
          assert.equal(err.message, 'Forbidden')
          assert.equal(res.text, undefined)
          done()
        } catch (e) {
          done(e)
        }
      }
      mws(req, res, next)
    })
  })
})
