/**
 * GET /api/users/search - Search for users with filtering and pagination
 *
 * Query Parameters:
 *   q       - Search query (email, name, or partial match)
 *   page    - Page number (default: 1)
 *   limit   - Results per page (default: 10, max: 100)
 *   role    - Filter by role (user|admin|driver)
 *   sortBy  - Sort field (name, email, createdAt; default: createdAt)
 *   order   - Sort order (asc|desc; default: desc)
 *
 * Examples:
 *   GET /api/users/search?q=john&role=driver&page=1&limit=20
 *   GET /api/users/search?sortBy=email&order=asc&limit=50
 */

module.exports = {
    path: 'GET /api/users/search',
    description:
        'Search and filter users with pagination and sorting support',
    auth: 'Required (authenticate middleware)',
    scope: 'Optional - returns all users by default, admin scope shows sensitive fields',

    queryParams: [
        {
            name: 'q',
            type: 'string',
            required: false,
            description:
                'Search query - matches against email and name (case-insensitive, partial match)',
            examples: ['john', 'doe@example.com', 'driver']
        },
        {
            name: 'page',
            type: 'number',
            required: false,
            default: 1,
            description: 'Page number for pagination',
            examples: [1, 2, 3]
        },
        {
            name: 'limit',
            type: 'number',
            required: false,
            default: 10,
            max: 100,
            description: 'Results per page (capped at 100)',
            examples: [10, 25, 50]
        },
        {
            name: 'role',
            type: 'enum',
            required: false,
            enum: ['user', 'admin', 'driver'],
            description: 'Filter by user role',
            examples: ['driver', 'admin']
        },
        {
            name: 'sortBy',
            type: 'enum',
            required: false,
            enum: ['name', 'email', 'createdAt'],
            default: 'createdAt',
            description: 'Field to sort by'
        },
        {
            name: 'order',
            type: 'enum',
            required: false,
            enum: ['asc', 'desc'],
            default: 'desc',
            description: 'Sort order (ascending or descending)'
        }
    ],

    examples: {
        basic: {
            request: 'GET /api/users/search?q=john',
            description: "Search for users matching 'john'",
            response: {
                status: 200,
                body: {
                    success: true,
                    data: {
                        users: [
                            {
                                id: 'user-123',
                                email: 'john@example.com',
                                name: 'John Doe',
                                role: 'driver',
                                createdAt: '2025-12-16T20:00:00Z'
                            },
                            {
                                id: 'user-456',
                                email: 'johnson@example.com',
                                name: 'Johnson Smith',
                                role: 'user',
                                createdAt: '2025-12-15T10:30:00Z'
                            }
                        ],
                        pagination: {
                            page: 1,
                            limit: 10,
                            total: 2,
                            totalPages: 1
                        }
                    }
                }
            }
        },

        filtered: {
            request:
                'GET /api/users/search?role=driver&sortBy=name&order=asc&limit=25',
            description: 'List all drivers, sorted by name, 25 per page',
            response: {
                status: 200,
                body: {
                    success: true,
                    data: {
                        users: [
                            {
                                id: 'driver-001',
                                email: 'alice@example.com',
                                name: 'Alice Brown',
                                role: 'driver',
                                createdAt: '2025-12-10T15:00:00Z'
                            }
                        ],
                        pagination: {
                            page: 1,
                            limit: 25,
                            total: 45,
                            totalPages: 2
                        }
                    }
                }
            }
        },

        paginated: {
            request: 'GET /api/users/search?page=2&limit=10',
            description: 'Second page of results, 10 per page',
            response: {
                status: 200,
                body: {
                    success: true,
                    data: {
                        users: [],
                        pagination: {
                            page: 2,
                            limit: 10,
                            total: 8,
                            totalPages: 1
                        }
                    }
                }
            }
        },

        errors: {
            invalidRole: {
                request: 'GET /api/users/search?role=superuser',
                status: 400,
                response: {
                    success: false,
                    error: 'Validation Error',
                    details: [
                        {
                            msg: 'Role must be one of: user, admin, driver',
                            path: 'role',
                            value: 'superuser'
                        }
                    ]
                }
            },

            pageOutOfRange: {
                request: 'GET /api/users/search?page=999',
                status: 200,
                response: {
                    success: true,
                    data: {
                        users: [],
                        pagination: {
                            page: 999,
                            limit: 10,
                            total: 8,
                            totalPages: 1
                        }
                    }
                }
            },

            limitExceeded: {
                request: 'GET /api/users/search?limit=200',
                status: 400,
                response: {
                    success: false,
                    error: 'Validation Error',
                    details: [
                        {
                            msg: 'Limit must not exceed 100',
                            path: 'limit',
                            value: 200
                        }
                    ]
                }
            },

            unauthorized: {
                request: 'GET /api/users/search (no auth header)',
                status: 401,
                response: {
                    success: false,
                    error: 'Unauthorized',
                    message: 'Authentication required'
                }
            }
        }
    },

    implementation: `
const { query, validationResult } = require("express-validator");
const prisma = require("../db");

router.get(
  "/users/search",
  authenticate,
  [
    query("q")
      .optional()
      .isString()
      .trim()
      .isLength({ min: 1, max: 100 })
      .withMessage("Search query must be 1-100 characters"),
    query("page")
      .optional()
      .isInt({ min: 1 })
      .toInt()
      .withMessage("Page must be a positive integer"),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .toInt()
      .withMessage("Limit must be 1-100"),
    query("role")
      .optional()
      .isIn(["user", "admin", "driver"])
      .withMessage("Role must be one of: user, admin, driver"),
    query("sortBy")
      .optional()
      .isIn(["name", "email", "createdAt"])
      .withMessage("Sort field must be: name, email, createdAt"),
    query("order")
      .optional()
      .isIn(["asc", "desc"])
      .withMessage("Order must be: asc or desc"),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          error: "Validation Error",
          details: errors.array(),
        });
      }

      const {
        q,
        page = 1,
        limit = 10,
        role,
        sortBy = "createdAt",
        order = "desc",
      } = req.query;

      // Build filter
      const where = {};
      if (q) {
        where.OR = [
          { email: { contains: q, mode: "insensitive" } },
          { name: { contains: q, mode: "insensitive" } },
        ];
      }
      if (role) {
        where.role = role;
      }

      // Get total count
      const total = await prisma.user.count({ where });

      // Get paginated results
      const users = await prisma.user.findMany({
        where,
        orderBy: { [sortBy]: order },
        skip: (page - 1) * limit,
        take: limit,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: req.user.scopes?.includes("admin") ? true : false, // Only admins see timestamps
        },
      });

      res.json({
        success: true,
        data: {
          users,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        },
      });
    } catch (err) {
      next(err);
    }
  },
);
`
}
