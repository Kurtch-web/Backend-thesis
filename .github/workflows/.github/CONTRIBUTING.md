# Contributing to LET AI Control Hub

Thank you for your interest in contributing to LET AI Control Hub! We welcome contributions from everyone.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Prepwise-LetAI.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Commit: `git commit -m "Description of changes"`
6. Push: `git push origin feature/your-feature-name`
7. Open a Pull Request

## Development Setup

### Frontend
```bash
cd frontend
pnpm install
pnpm run dev
```

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Code Standards

### Frontend
- Use **TypeScript** for type safety
- Follow **ESLint** configuration
- Use **Tailwind CSS** for styling
- Components should be in `src/components/`
- Pages should be in `src/views/`

### Backend
- Follow **PEP 8** style guide
- Use **type hints** for functions
- Keep business logic in `app/services/`
- API routes in `app/routers/`

## Commit Messages

Use clear, descriptive commit messages:
- `feat: Add new authentication feature`
- `fix: Resolve login button issue`
- `docs: Update README with deployment steps`
- `refactor: Improve API client performance`
- `test: Add unit tests for password reset`

## Pull Request Process

1. Update the README.md with any new features
2. Ensure all tests pass
3. Update documentation if needed
4. Describe your changes clearly in the PR description
5. Link any related issues

## Reporting Issues

When reporting bugs, please include:
- Clear description of the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Screenshots (if applicable)
- Your environment (OS, browser, etc.)

## Questions?

Feel free to open an issue or reach out to the maintainers.

---

**Happy contributing! 🚀**
