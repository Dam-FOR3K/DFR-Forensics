# Contributing to DFR-Forensics 🛡️

Thank you for your interest in contributing to **DFR-Forensics** (*Disk & File Resurrection*)! This project aims to provide high-performance, non-destructive low-level triage, filesystem reconstruction, and resilient carving for forensic analysts and incident responders worldwide.

---

## 🛠️ Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Dam-FOR3K/DFR-Forensics.git
   cd DFR-Forensics
   ```

2. **Set up a Python virtual environment (Python 3.10+ recommended):**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux / macOS
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🧪 Running Tests

Before submitting any pull request, ensure all test suites pass:

```bash
pytest tests/ -v
```

---

## 📐 Code Guidelines

- **Forensic Safety First**: All image readers (`ForensicImageReader`) must operate in **strict read-only mode** (`'rb'`). Never write directly to target evidence files.
- **UEFI Compliance**: Keep binary packing and unpack routines fully aligned with the UEFI 2.10 specification (Little-Endian, zeroed CRC during header calculation).
- **Internationalization (i18n)**: All new user-facing messages and UI labels must be registered in `core/i18n.py` with both French (`fr`) and English (`en`) translations.

---

## 📄 Pull Request Process

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes with clear, descriptive commit messages.
3. Push to your fork and submit a Pull Request.
