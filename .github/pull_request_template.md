# Pull Request

## 📝 Description
Brief description of the changes in this PR.

## 🔗 Related Issues
Fixes #(issue number)
Relates to #(issue number)

## 🎯 Type of Change
Please delete options that are not relevant:
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test improvements

## 🧪 Testing
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have tested this change with real log files

### Test Details
Describe the tests you ran to verify your changes:
```bash
# Example commands you used to test
poetry run pytest tests/test_new_feature.py -v
loglens analyze sample_logs/test.log --verbose
```

## 📋 Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## 🔧 Code Quality
- [ ] `poetry run black src/ tests/` (code formatting)
- [ ] `poetry run flake8 src/ tests/` (linting)
- [ ] `poetry run mypy src/` (type checking)
- [ ] `poetry run pytest --cov=loglens` (test coverage)

## 📊 Performance Impact
If this change affects performance, please describe:
- [ ] Performance improvement
- [ ] No performance impact
- [ ] Potential performance regression (explain below)

### Performance Details
[Describe any performance implications]

## 🔒 Security Considerations
- [ ] This change does not introduce security vulnerabilities
- [ ] I have considered the security implications of this change
- [ ] Any new dependencies have been security reviewed

## 📚 Documentation
- [ ] I have updated the README.md if needed
- [ ] I have updated the API documentation if needed
- [ ] I have updated the CHANGELOG.md
- [ ] I have added/updated docstrings for new functions

## 🖼️ Screenshots (if applicable)
Add screenshots to help explain your changes.

## 📝 Additional Notes
Any additional information, context, or screenshots about the pull request here. 