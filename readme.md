# @veloze/access-control

> attribute- or role-based access control

Works on any connect based routers, like [express][], [veloze][].

Uses [@casl/ability][casl-ability].

[express]: https://expressjs.com
[veloze]: https://github.com/commenthol/veloze
[casl-ability]: https://casl.js.org

## usage

```js
import { authorize, allow, allowedSubject, 
  createAbilityBuilder } from '@veloze/access-control'
import { Router, HttpError } from 'veloze'

/**
 * define permissions by role.
 */
async function defineAbilityFor (jwtClaims) {
  const { can, cannot, build } = createAbilityBuilder()
  const { roles } = jwtClaims
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

const router = new Router()
router.use(
  // verify session or token; here `req.auth` contains claims payload from JWT
  protect(...), // e.g. from `@veloze/jwt`
  // add access attributes
  authorize(defineAbilityFor)
)

router.get('/articles/:articleId', 
  // general read access on articles is checked
  allow([{ action: 'read', subject: 'Article' }]), 
  // load article by articleId
  async (req, res) => {
    // article instanceOf Article
    const article = await db.find(req.params.articleId) 
    // check if access to private articles is given.
    if (!req.ability?.can('read', article, { private: true })) {
      throw HttpError(403, 'You are not allowed to read private articles')
    }    
    res.end(article.text)
  }
)

router.post('/articles', 
  // OR use correct action from req.method; POST method uses 'create'
  allowSubject('Article'),
  async (req, res) => {
    ...
  }
)
```

## license

MIT
