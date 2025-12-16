# Zod Validation Guide

## Overview

Zod is a TypeScript-first schema validation library that provides runtime type safety and excellent error messages. This project uses Zod for request validation across all API endpoints.

## Why Zod?

✅ **Type-safe** - Automatic TypeScript type inference  
✅ **Better errors** - Clear, actionable error messages  
✅ **Composable** - Build complex schemas from simple ones  
✅ **Transformations** - Parse and transform data automatically  
✅ **Zero dependencies** - Small bundle size  

## Basic Usage

### Simple Schema Validation

```javascript
const { validateBody } = require('./middleware/zodValidation');
const { z } = require('./middleware/zodValidation');

const UserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
  age: z.number().int().positive()
});

router.post('/users', validateBody(UserSchema), (req, res) => {
  // req.body is now validated and typed
  const { email, name, age } = req.body;
  res.json({ success: true });
});
```

### Validation Response

**Invalid Request**:
```json
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR",
  "details": [
    {
      "location": "body",
      "issues": [
        {
          "path": "email",
          "message": "Invalid email",
          "code": "invalid_string"
        },
        {
          "path": "name",
          "message": "String must contain at least 2 character(s)",
          "code": "too_small"
        }
      ]
    }
  ]
}
```

## Available Schemas

### AI Command Schema

```javascript
const { AiCommandSchema } = require('./middleware/schemas');

// Validates:
// - command: string (1-200 chars, alphanumeric + _ -)
// - payload: optional record
// - meta: optional record

router.post('/ai/command', validateBody(AiCommandSchema), handler);
```

**Example Request**:
```json
{
  "command": "analyze_shipment",
  "payload": {
    "shipmentId": "123",
    "priority": "high"
  },
  "meta": {
    "source": "web"
  }
}
```

### User Schemas

```javascript
const { UserCreateSchema, UserUpdateSchema } = require('./middleware/schemas');

// Create user
router.post('/users', validateBody(UserCreateSchema), handler);

// Update user
router.patch('/users/:id', validateBody(UserUpdateSchema), handler);
```

**User Create**:
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "SecurePass123",
  "role": "user"
}
```

### Shipment Schema

```javascript
const { ShipmentSchema } = require('./middleware/schemas');

router.post('/shipments', validateBody(ShipmentSchema), handler);
```

**Shipment**:
```json
{
  "origin": "New York, NY",
  "destination": "Los Angeles, CA",
  "weight": 50.5,
  "dimensions": {
    "length": 100,
    "width": 50,
    "height": 30,
    "unit": "cm"
  },
  "priority": "urgent"
}
```

### Pagination Schema

```javascript
const { PaginationSchema } = require('./middleware/schemas');

router.get('/users', validateQuery(PaginationSchema), handler);
```

**Query Parameters**:
```
GET /users?page=2&limit=20&sortBy=createdAt&order=desc
```

## Validation Middleware

### validateBody(schema)

Validates request body:

```javascript
const { validateBody, z } = require('./middleware/zodValidation');

const schema = z.object({
  title: z.string(),
  content: z.string()
});

router.post('/posts', validateBody(schema), handler);
```

### validateQuery(schema)

Validates query parameters:

```javascript
const { validateQuery, z } = require('./middleware/zodValidation');

const schema = z.object({
  page: z.string().regex(/^\d+$/),
  search: z.string().optional()
});

router.get('/search', validateQuery(schema), handler);
```

### validateParams(schema)

Validates route parameters:

```javascript
const { validateParams } = require('./middleware/zodValidation');
const { IdParamSchema } = require('./middleware/schemas');

router.get('/users/:id', validateParams(IdParamSchema), handler);
```

### validateRequest(schemas)

Validates multiple parts of request:

```javascript
const { validateRequest, z } = require('./middleware/zodValidation');

router.post('/users/:id/posts',
  validateRequest({
    params: z.object({ id: z.string().uuid() }),
    body: z.object({ title: z.string() }),
    query: z.object({ publish: z.string().optional() })
  }),
  handler
);
```

## Creating Custom Schemas

### Basic Schema

```javascript
const { z } = require('./middleware/zodValidation');

const ProductSchema = z.object({
  name: z.string().min(1).max(100),
  price: z.number().positive(),
  category: z.enum(['electronics', 'clothing', 'food']),
  inStock: z.boolean().default(true)
});
```

### With Transformations

```javascript
const DateRangeSchema = z.object({
  startDate: z.string()
    .datetime()
    .transform(str => new Date(str)),
  
  endDate: z.string()
    .datetime()
    .transform(str => new Date(str))
}).refine(
  data => data.endDate > data.startDate,
  "End date must be after start date"
);
```

### Nested Objects

```javascript
const AddressSchema = z.object({
  street: z.string(),
  city: z.string(),
  state: z.string().length(2),
  zip: z.string().regex(/^\d{5}$/)
});

const UserWithAddressSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  address: AddressSchema
});
```

### Arrays

```javascript
const OrderSchema = z.object({
  items: z.array(z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().positive()
  })).min(1, "Order must have at least one item"),
  
  totalAmount: z.number().positive()
});
```

### Optional Fields

```javascript
const ProfileSchema = z.object({
  // Required
  username: z.string(),
  
  // Optional (can be undefined)
  bio: z.string().optional(),
  
  // With default value
  theme: z.enum(['light', 'dark']).default('light'),
  
  // Nullable (can be null)
  avatar: z.string().url().nullable()
});
```

## Advanced Validation

### Custom Refinements

```javascript
const PasswordSchema = z.object({
  password: z.string().min(8),
  confirmPassword: z.string()
}).refine(
  data => data.password === data.confirmPassword,
  {
    message: "Passwords don't match",
    path: ["confirmPassword"]
  }
);
```

### Conditional Validation

```javascript
const PaymentSchema = z.discriminatedUnion('method', [
  z.object({
    method: z.literal('card'),
    cardNumber: z.string().length(16),
    cvv: z.string().length(3)
  }),
  z.object({
    method: z.literal('paypal'),
    email: z.string().email()
  })
]);
```

### Union Types

```javascript
const IdSchema = z.union([
  z.string().uuid(),
  z.string().regex(/^\d+$/).transform(Number)
]);
```

### Preprocessing

```javascript
const TrimmedStringSchema = z.string()
  .trim()
  .min(1, "Cannot be empty");

const UppercaseSchema = z.string()
  .transform(s => s.toUpperCase());
```

## Testing with Zod

### Unit Test Example

```javascript
const { AiCommandSchema } = require('./middleware/schemas');

describe('AiCommandSchema', () => {
  it('should validate valid command', () => {
    const result = AiCommandSchema.safeParse({
      command: 'test_command',
      payload: { data: 'test' }
    });
    
    expect(result.success).toBe(true);
  });

  it('should reject invalid command', () => {
    const result = AiCommandSchema.safeParse({
      command: '',
      payload: 'not-an-object'
    });
    
    expect(result.success).toBe(false);
    expect(result.error.issues).toHaveLength(2);
  });
});
```

### Integration Test

```javascript
const request = require('supertest');
const app = require('./server');

describe('POST /api/ai/command', () => {
  it('should return 400 for invalid payload', async () => {
    const response = await request(app)
      .post('/api/ai/command')
      .send({ command: '' });
    
    expect(response.status).toBe(400);
    expect(response.body.code).toBe('VALIDATION_ERROR');
  });
});
```

## Migration from express-validator

### Before (express-validator)

```javascript
const { body, validationResult } = require('express-validator');

router.post('/users',
  [
    body('email').isEmail(),
    body('name').isLength({ min: 2 }),
    (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      next();
    }
  ],
  handler
);
```

### After (Zod)

```javascript
const { validateBody, z } = require('./middleware/zodValidation');

const UserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2)
});

router.post('/users', validateBody(UserSchema), handler);
```

## Best Practices

### 1. Reuse Common Schemas

```javascript
// Create reusable parts
const EmailSchema = z.string().email();
const UuidSchema = z.string().uuid();

// Compose into larger schemas
const UserSchema = z.object({
  id: UuidSchema,
  email: EmailSchema
});
```

### 2. Provide Helpful Error Messages

```javascript
const PasswordSchema = z.string()
  .min(8, "Password must be at least 8 characters")
  .regex(/[A-Z]/, "Password must contain uppercase letter")
  .regex(/[a-z]/, "Password must contain lowercase letter")
  .regex(/\d/, "Password must contain number");
```

### 3. Use Defaults Wisely

```javascript
const QuerySchema = z.object({
  page: z.string().default('1'),
  limit: z.string().default('10'),
  includeDeleted: z.boolean().default(false)
});
```

### 4. Validate Early

```javascript
// Validate at route entry, not in business logic
router.post('/resource', validateBody(schema), handler);
```

### 5. Document with JSDoc

```javascript
/**
 * @typedef {z.infer<typeof UserSchema>} User
 */
const UserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email()
});
```

## Performance Considerations

- Zod validation is fast (~1-2ms for typical schemas)
- Schemas are compiled once and reused
- Use `.transform()` sparingly in hot paths
- Cache complex schemas at module level

## Related Files

- [middleware/zodValidation.js](zodValidation.js) - Validation middleware
- [middleware/schemas.js](schemas.js) - Predefined schemas
- [api/ai.commands.js](../api/ai.commands.js) - Example usage

## Further Reading

- [Zod Documentation](https://zod.dev/)
- [Zod GitHub](https://github.com/colinhacks/zod)
- [Type-safe API Design](https://www.typescriptlang.org/docs/handbook/2/narrowing.html)
