# 🤝 Contributing to Bug Scan Pro

<div align="center">

**Made with ❤️ by [@lonefaisal](https://t.me/lonefaisal)**

[![ARROW NETWORK](https://img.shields.io/badge/Telegram-ARROW%20NETWORK-blue?style=for-the-badge&logo=telegram)](https://t.me/arrow_network)
[![KMRI NETWORK](https://img.shields.io/badge/Telegram-KMRI%20NETWORK-green?style=for-the-badge&logo=telegram)](https://t.me/kmri_network_reborn)

</div>

---

## 🎯 Welcome Contributors!

We're excited that you're interested in contributing to **Bug Scan Pro**! This document will guide you through the process of contributing to this professional security testing toolkit.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git knowledge
- Basic understanding of async programming
- Cybersecurity knowledge (preferred)

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/lonefaisal7/bug-scan-Pro.git
cd bug-scan-Pro

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio black flake8 mypy

# Run tests to ensure everything works
python -m pytest tests/
```

---

## 📝 Code Guidelines

### Coding Standards
- **Follow PEP 8**: Use `black` for automatic formatting
- **Type Hints**: All functions must include type hints
- **Docstrings**: Comprehensive docstrings for all classes and functions
- **Async/Await**: Maintain async/await throughout the codebase
- **Error Handling**: Comprehensive error handling with graceful failures

### Code Style Example
```python
async def example_function(
    hostname: str,
    port: int = 80,
    timeout: int = 10
) -> Dict[str, Any]:
    """Example function with proper style.
    
    Args:
        hostname: The target hostname to scan
        port: Port number to check (default: 80)
        timeout: Request timeout in seconds (default: 10)
    
    Returns:
        Dictionary containing scan results
    
    Raises:
        ValueError: If hostname is invalid
        asyncio.TimeoutError: If request times out
    """
    if not is_valid_hostname(hostname):
        raise ValueError(f"Invalid hostname: {hostname}")
    
    try:
        # Implementation here
        result = await perform_scan(hostname, port, timeout)
        return result
    except Exception as e:
        logger.error(f"Scan failed for {hostname}:{port} - {e}")
        raise
```

---

## 🎨 Contribution Types

### 🐛 Bug Reports
- Use the GitHub issue template
- Provide detailed reproduction steps
- Include system information
- Attach relevant logs or screenshots

### ✨ Feature Requests
- Describe the feature and its benefits
- Provide use cases and examples
- Consider security implications
- Suggest implementation approach

### 🔧 Code Contributions
- **Core Modules**: DNS resolver, HTTP checker, SSL analyzer
- **Scanning Engines**: Port scanner, CIDR scanner, subdomain finder
- **Output Formats**: New export formats and reporting
- **Passive Sources**: New passive reconnaissance sources
- **Plugins**: Custom scanning plugins and extensions

### 📚 Documentation
- Improve README and documentation
- Add usage examples and tutorials
- Create video demonstrations
- Write technical blog posts

---

## 🔄 Development Workflow

### 1. Fork & Branch
```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or bug fix branch
git checkout -b bugfix/issue-description
```

### 2. Development
```bash
# Make your changes
# Add comprehensive tests
# Update documentation

# Format code
black bugscanpro/

# Check style
flake8 bugscanpro/

# Type checking
mypy bugscanpro/

# Run tests
python -m pytest tests/
```

### 3. Commit & Push
```bash
# Commit with descriptive message
git add .
git commit -m "feat: add advanced proxy rotation system"

# Push to your fork
git push origin feature/your-feature-name
```

### 4. Pull Request
- Create detailed pull request description
- Link related issues
- Add screenshots/demos if applicable
- Ensure all tests pass

---

## 🧪 Testing Guidelines

### Test Structure
```python
import pytest
import asyncio
from unittest.mock import Mock, patch

from bugscanpro.scanner import Scanner


class TestScanner:
    @pytest.mark.asyncio
    async def test_basic_scanning(self):
        """Test basic scanning functionality"""
        scanner = Scanner()
        result = await scanner.scan_hostname("example.com")
        
        assert result is not None
        assert 'host' in result
        assert result['host'] == "example.com"
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling"""
        scanner = Scanner()
        
        with pytest.raises(ValueError):
            await scanner.scan_hostname("invalid..hostname")
```

### Running Tests
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=bugscanpro

# Run specific test file
python -m pytest tests/test_scanner.py

# Run async tests only
python -m pytest -m asyncio
```

---

## 📋 Issue Templates

### Bug Report Template
```markdown
## 🐛 Bug Description
[Clear description of the bug]

## 🔄 Steps to Reproduce
1. Step one
2. Step two
3. Step three

## ✅ Expected Behavior
[What should happen]

## ❌ Actual Behavior
[What actually happens]

## 💻 Environment
- OS: [e.g., Ubuntu 20.04]
- Python: [e.g., 3.9.0]
- Bug Scan Pro Version: [e.g., 1.0.0]

## 📄 Additional Context
[Any additional information]
```

### Feature Request Template
```markdown
## 🚀 Feature Description
[Detailed description of the proposed feature]

## 🎯 Use Case
[Why is this feature needed?]

## 💡 Proposed Implementation
[How should this be implemented?]

## 🔒 Security Considerations
[Any security implications]

## 📊 Additional Context
[Screenshots, mockups, examples]
```

---

## 🏆 Recognition

### Contributors Hall of Fame
- All contributors will be listed in the README
- Significant contributions get special recognition
- Top contributors get direct contact with @lonefaisal

### Contribution Levels
- **🥇 Gold**: Major features, architectural improvements
- **🥈 Silver**: Bug fixes, documentation, testing
- **🥉 Bronze**: Minor fixes, suggestions, issue reporting

---

## 📞 Getting Help

### Communication Channels
- **📧 Issues**: Use GitHub Issues for bug reports
- **💬 Discussions**: GitHub Discussions for general questions
- **📱 Telegram**: Direct message [@lonefaisal](https://t.me/lonefaisal)
- **🌐 Networks**: Join [ARROW](https://t.me/arrow_network) or [KMRI](https://t.me/kmri_network_reborn)

### Response Times
- **Bug reports**: Within 24-48 hours
- **Feature requests**: Within 1 week
- **Pull requests**: Within 1 week
- **General questions**: Within 24 hours

---

## ⚖️ Code of Conduct

### Our Standards
- **Be respectful** and inclusive
- **Be constructive** in feedback
- **Follow ethical hacking** principles
- **Respect privacy** and security
- **Give credit** where due

### Enforcement
Violations of the code of conduct may result in temporary or permanent exclusion from the project community.

---

## 🎖️ Special Thanks

### Powered By
- **🌟 ARROW NETWORK**: Advanced security research community
- **🔥 KMRI NETWORK**: Cybersecurity professionals network

### Creator
- **👨‍💻 LONE FAISAL (@lonefaisal)**: Project creator and maintainer
- **📱 Telegram**: [@lonefaisal](https://t.me/lonefaisal)
- **🐙 GitHub**: [lonefaisal7](https://github.com/lonefaisal7)

---

<div align="center">

**Thank you for contributing to Bug Scan Pro!** 🙏

**Made with ❤️ by [@lonefaisal](https://t.me/lonefaisal) | Professional Security Research 2025**

</div>