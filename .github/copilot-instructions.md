# GitHub Copilot Instructions for Infamous Freight Enterprises

## Project Overview

This is a modern full-stack freight management platform built as a pnpm monorepo with:

- **Backend**: Node.js/Express API with PostgreSQL/Prisma
- **Frontend**: Next.js/React with TypeScript
- **Mobile**: React Native/Expo application
- **Shared**: Common types, utilities, and constants package

## Development Workflow

### Initial Setup ✓

- [x] Project scaffolded and configured
- [x] Monorepo structure with pnpm workspaces
- [x] Shared package created
- [x] CI/CD pipeline configured
- [x] Documentation complete

### Next Steps - Development Cycle

When working on new features or fixes:

- [ ] **Understand the Task**
  - Review issue/requirement details
  - Check related code in api/, web/, or mobile/
  - Review shared package for reusable code

- [ ] **Setup Development Environment**

  ```bash
  pnpm install              # Install dependencies
  pnpm dev                  # Start all services (or api:dev, web:dev)
  ```

- [ ] **Create Feature Branch**
  - Use conventional naming: `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, `chore/`
  - Example: `feat/add-shipment-tracking`

- [ ] **Make Changes**
  - Follow existing code patterns
  - Use shared package for common code: `@infamous-freight/shared`
  - Write clean, maintainable code
  - Add JSDoc comments for public APIs
  - Update related documentation

- [ ] **Write/Update Tests**
  - Add tests for new functionality
  - Maintain or improve test coverage
  - Run: `pnpm test` or `pnpm --filter <package> test`

- [ ] **Code Quality Checks**

  ```bash
  pnpm lint                 # Check for issues
  pnpm lint:fix             # Auto-fix linting issues
  pnpm format               # Format code with Prettier
  pnpm check:types          # TypeScript type checking
  pnpm test                 # Run all tests
  ```

- [ ] **Commit Changes**
  - Use conventional commit format: `type(scope): description`
  - Examples:
    - `feat(api): add shipment tracking endpoint`
    - `fix(web): resolve button alignment issue`
    - `docs: update API documentation`
  - Pre-commit hooks automatically run linting and formatting

- [ ] **Test Locally**
  - Verify changes in development environment
  - Test edge cases and error handling
  - Check mobile responsiveness if UI changes
  - Review database migrations if schema changes

- [ ] **Create Pull Request**
  - Use clear, descriptive title
  - Fill out PR template
  - Reference related issues
  - Add screenshots for UI changes
  - Wait for CI checks to pass

- [ ] **Address Review Feedback**
  - Respond to reviewer comments
  - Make requested changes
  - Re-run tests and checks
  - Update PR description if scope changes

## Common Development Tasks

### Working with Shared Package

```bash
# After modifying packages/shared
cd packages/shared
pnpm build
# or from root
pnpm --filter @infamous-freight/shared build
```

### Database Changes

```bash
cd api
pnpm prisma:migrate:dev   # Create and run migration
pnpm prisma:generate      # Regenerate Prisma client
pnpm prisma:studio        # Open database GUI
```

### Adding Dependencies

```bash
pnpm --filter api add <package>           # To API
pnpm --filter web add <package>           # To Web
pnpm --filter @infamous-freight/shared add <package>  # To Shared
pnpm add -w <package>                     # To workspace root
```

### Running Specific Services

```bash
pnpm api:dev              # Backend only (port 3001)
pnpm web:dev              # Frontend only (port 3000)
pnpm dev                  # All services
```

### Troubleshooting

```bash
# Shared package not found
pnpm --filter @infamous-freight/shared build

# Clean and reinstall
pnpm clean && pnpm install

# Regenerate Prisma client
cd api && pnpm prisma:generate
```

## Code Standards

- **Code Style**: ESLint + Prettier (auto-format on save)
- **TypeScript**: Use strict mode, avoid `any`, define interfaces
- **Commits**: Conventional Commits format
- **Testing**: Write tests for new features
- **Documentation**: Update docs for API/feature changes

## Project Structure

```
├── api/                  # Backend API service
│   ├── src/             # Source code
│   └── prisma/          # Database schema
├── web/                 # Next.js frontend
│   ├── pages/          # Routes
│   └── components/     # React components
├── mobile/             # React Native app
├── packages/shared/    # Shared code
│   ├── src/types.ts    # Common types
│   ├── src/utils.ts    # Utilities
│   └── src/constants.ts # Constants
└── e2e/                # E2E tests
```

## Helpful Resources

- [README.md](README.md) - Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command reference
- [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) - All documentation

## Guidelines

- Keep responses concise and focused
- Follow existing patterns in the codebase
- Test changes before committing
- Update documentation when needed
- Ask for clarification when requirements are unclear
- Work through tasks systematically
- Maintain code quality and test coverage
