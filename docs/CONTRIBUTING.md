# NTP-SCTAP Contributing Guide

> Guidelines for contributing to the NTP-SCTAP project.  
> Last updated: 2026-06-29

---

## Development Workflow

1. Create a feature branch from `main`
2. Implement changes following project coding standards
3. Write/update tests for all new code
4. Ensure all tests pass: `pytest -v`
5. Update documentation (project_structure.md, progress_file.md, etc.)
6. Submit a pull request with a clear description

## Coding Standards

- Python 3.10+ type hints on all function signatures
- Docstrings on all public classes and functions
- One class per responsibility
- One function per task
- No placeholder implementations
- No duplicated logic
- Professional comments only where necessary

## Testing Requirements

- All new modules must have corresponding test files
- Use pytest fixtures from `tests/conftest.py`
- Aim for >90% coverage on core modules

## Documentation Requirements

When code changes, immediately update:
- `docs/project_structure.md` — if files are added, modified, or removed
- `docs/progress_file.md` — record the work done
- `docs/CHANGELOG.md` — note what changed
- `docs/API_REFERENCE.md` — if API endpoints change
- `README.md` — if features or setup instructions change
