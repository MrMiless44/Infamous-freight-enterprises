# Repository Restructuring Migration Notes

## Overview

The repository has been restructured to improve organization and maintainability. This document describes the changes and any actions you may need to take.

## What Changed

### 1. Configuration Files Organization

All configuration files have been moved to the `configs/` directory:

- `configs/docker/` - Docker Compose configurations
- `configs/ci-cd/` - CI/CD platform configurations
- `configs/linting/` - Linting and code quality tools

**Important**: Symlinks have been created at the root level for tools that require configuration files there. This means your existing workflows should continue to work without changes.

### 2. Documentation Organization

Documentation has been organized into logical subdirectories:

- `docs/api/` - API documentation
- `docs/deployment/` - Deployment guides
- `docs/development/` - Development guides
- `docs/sessions/` - Historical session notes
- `docs/testing/` - Testing documentation

New documentation has been added:

- `docs/developer-guide.md` - Comprehensive setup guide
- `docs/repository-structure.md` - Repository organization
- `docs/validation-guide.md` - Code validation guide
- `docs/README.md` - Documentation index

### 3. Temporary Files Cleanup

Removed temporary and invalid files:

- `Untitled-*` files
- `.pid` files
- Malformed filenames with special characters

### 4. Enhanced CI/CD

- Added CSS validation with Stylelint
- Enhanced validation documentation
- All validation steps documented in `docs/validation-guide.md`

### 5. Naming Conventions

Standardized naming conventions:

- Configuration files: kebab-case or dot-prefix
- Scripts: kebab-case with `.sh` extension
- Documentation: UPPERCASE with underscores for important files

## Do You Need to Do Anything?

### For Most Users: No Action Required

If you're working with the repository normally, **no action is needed**. Symlinks ensure that:

- Docker Compose commands still work
- ESLint still finds its configuration
- Playwright still works
- All tools function as before

### If You Reference Config Files Directly

If you have scripts or documentation that reference configuration files by path, you may need to update them:

**Old paths** → **New paths:**

- `docker-compose.yml` → `configs/docker/docker-compose.yml` (symlink at root still works)
- `eslint.config.js` → `configs/linting/eslint.config.js` (symlink at root still works)
- `codecov.yml` → `configs/ci-cd/codecov.yml` (symlink at root still works)

**Note**: You can continue using the root-level paths thanks to symlinks, but prefer using the new paths in new code.

### If You Have Local Modifications

If you have local modifications to configuration files:

1. Your changes are safe - symlinks point to the real files
2. Edit files in `configs/` directory, not the symlinks
3. Your git operations will work normally

### If You Have Custom Scripts

If you have custom scripts that reference moved files:

1. Update paths to point to `configs/` directory if needed
2. Or rely on symlinks (recommended)
3. Test your scripts after pulling changes

## Benefits of This Restructuring

1. **Cleaner Root Directory**: Easier to find important files
2. **Better Organization**: Related files are grouped together
3. **Improved Documentation**: Comprehensive guides and index
4. **Enhanced Validation**: CSS validation added, all tools documented
5. **Easier Maintenance**: Clear structure for future additions
6. **Better Onboarding**: New developers can find what they need faster

## Verifying Your Setup

After pulling these changes, verify everything works:

```bash
# Verify symlinks
ls -la *.yml *.js | grep "^l"

# Should show symlinks to configs/ directory

# Verify Docker Compose
docker-compose config --services

# Should list services without errors

# Verify ESLint
cat eslint.config.js

# Should show the configuration (via symlink)

# Verify documentation
ls docs/
ls docs/api/
ls docs/deployment/

# Should show organized documentation
```

## Common Issues and Solutions

### Issue: "Config file not found"

**Solution**: Ensure symlinks are created. Run:

```bash
ls -la *.yml *.js | grep "^l"
```

If symlinks are missing, they may have been deleted. Pull the latest changes again or recreate them manually.

### Issue: "Documentation links broken"

**Solution**: Documentation has been moved. Check `docs/README.md` for the new locations. Update any bookmarks or references.

### Issue: "Git shows many deleted files"

**Solution**: This is normal after the restructuring. These files have been moved, not deleted. Run `git status` to see the moves/renames.

## Getting Help

If you encounter issues after this restructuring:

1. Check this migration guide
2. Review `docs/repository-structure.md` for file locations
3. Check `docs/developer-guide.md` for setup instructions
4. Open an issue on GitHub if problems persist

## Timeline

- **Restructuring implemented**: December 25, 2024
- **Breaking changes**: None (symlinks maintain compatibility)
- **Migration required**: No mandatory migration
- **Recommended actions**: Update documentation bookmarks

## Future Changes

This restructuring sets the foundation for:

- Easier addition of new configuration files
- Better documentation maintenance
- Improved developer experience
- Clearer project structure

## Questions?

See the [Developer Guide](docs/developer-guide.md) or open a GitHub Discussion.
