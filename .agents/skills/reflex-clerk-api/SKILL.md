```markdown
# reflex-clerk-api Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `reflex-clerk-api` Python codebase. You'll learn about file naming, import/export styles, commit message conventions, and how to structure and run tests. This guide is ideal for contributors aiming to maintain consistency and quality in this repository.

## Coding Conventions

### File Naming
- Use **snake_case** for all Python files.
  - Example: `user_service.py`, `api_utils.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .models import User
    from .utils import parse_request
    ```

### Export Style
- Use **named exports** by explicitly listing exported symbols in `__all__`.
  - Example:
    ```python
    __all__ = ["UserService", "parse_request"]
    ```

### Commit Messages
- Follow **conventional commit** patterns.
- Use the `fix` prefix for bug fixes.
- Keep commit messages concise (average 72 characters).
  - Example:
    ```
    fix: handle missing user_id in request payload
    ```

## Workflows

### Fixing a Bug
**Trigger:** When you identify and resolve a bug in the codebase  
**Command:** `/fix-bug`

1. Create a new branch for your fix.
2. Make code changes following the coding conventions.
3. Write or update tests in files matching `*.test.*`.
4. Commit your changes using the `fix:` prefix.
    - Example: `fix: correct API response for empty input`
5. Push your branch and open a pull request.

### Adding a New Module
**Trigger:** When you need to add a new feature or module  
**Command:** `/add-module`

1. Create a new Python file using snake_case naming.
2. Use relative imports for internal dependencies.
3. Define `__all__` for named exports.
4. Add or update relevant test files (`*.test.*`).
5. Commit with a descriptive message (e.g., `feat: add payment processing module`).
6. Push and open a pull request.

## Testing Patterns

- Test files follow the pattern: `*.test.*` (e.g., `user_service.test.py`).
- The specific testing framework is **unknown**; check existing test files for patterns.
- Place tests alongside or within a dedicated `tests/` directory if present.
- Ensure new features and fixes include corresponding tests.

## Commands
| Command      | Purpose                                      |
|--------------|----------------------------------------------|
| /fix-bug     | Start the bug fix workflow                   |
| /add-module  | Start the new module/feature workflow        |
```
