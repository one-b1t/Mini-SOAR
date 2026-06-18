# CI/CD Pipeline Enhancement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate security scans, linting, type checks, and draft unit testing into GitLab CI and GitHub Actions pipelines for MiniSOAR.

**Architecture:** Implement a modular pipeline structure. GitLab CI gets stages: `security` (Gitleaks, Bandit), `lint` (Ruff, Mypy), `sonarqube` (existing), and `test` (Pytest draft, manual, allow failure). GitHub Actions gets equivalent jobs under `.github/workflows/ci.yml`.

**Tech Stack:** GitLab CI, GitHub Actions, Python, Gitleaks, Bandit, Ruff, Mypy, Pytest.

---

## Chunk 1: GitLab CI & GitHub Actions Setup

### Task 1: Update GitLab CI configuration
**Files:**
- Modify: `.gitlab-ci.yml`

- [ ] **Step 1: Replace .gitlab-ci.yml content**
  Replace `.gitlab-ci.yml` with the modular pipeline config.

  ```yaml
  stages:
    - security
    - lint
    - sonarqube
    - test

  # ==================== STAGE: SECURITY ====================

  gitleaks-scan:
    stage: security
    image:
      name: zricethezav/gitleaks:latest
      entrypoint: [""]
    script:
      - gitleaks detect --verbose --source .

  bandit-scan:
    stage: security
    image: python:3.10-slim
    script:
      - pip install bandit
      - bandit -r minisoar/

  # ==================== STAGE: LINT ====================

  ruff-check:
    stage: lint
    image: python:3.10-slim
    script:
      - pip install ruff
      - ruff check minisoar/
      - ruff format --check minisoar/

  mypy-check:
    stage: lint
    image: python:3.10-slim
    script:
      - pip install -r requirements.txt
      - pip install mypy types-redis types-requests types-PyYAML
      - mypy minisoar/

  # ==================== STAGE: SONARQUBE ====================

  sonarqube-check:
    stage: sonarqube
    tags:
      - sonar-scanner
    image:
      name: sonarsource/sonar-scanner-cli:latest
      entrypoint: [""]
    variables:
      SONAR_USER_HOME: "${CI_PROJECT_DIR}/.sonar"
      GIT_DEPTH: "0"
    cache:
      key: "sonar-${CI_PROJECT_ID}"
      paths:
        - .sonar/cache
    script:
      - echo "SONAR_HOST_URL=${SONAR_HOST_URL}"
      - echo "SONAR_TOKEN_LENGTH=${#SONAR_TOKEN}"
      - |
        sonar-scanner \
          -Dsonar.host.url="${SONAR_HOST_URL}" \
          -Dsonar.token="${SONAR_TOKEN}" \
          -Dsonar.projectKey="${CI_PROJECT_PATH_SLUG}" \
          -Dsonar.projectName="${CI_PROJECT_PATH}" \
          -Dsonar.sources=. \
          -Dsonar.qualitygate.wait=true
    only:
      - dev

  # ==================== STAGE: TEST (DRAFT) ====================

  pytest-run:
    stage: test
    image: python:3.10-slim
    script:
      - pip install -r requirements.txt
      - pip install pytest
      - pytest
    rules:
      - when: manual
        allow_failure: true
  ```

- [ ] **Step 2: Commit GitLab CI change**
  Run command:
  ```bash
  git add .gitlab-ci.yml
  git commit -m "ci: enhance gitlab pipeline with modular scan, lint, and draft test stages"
  ```

### Task 2: Create GitHub Actions workflow
**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write GitHub Action workflow file**
  Create the directory `.github/workflows` and file `.github/workflows/ci.yml` with the following configuration:

  ```yaml
  name: CI Pipeline

  on:
    push:
      branches: [ dev ]
    pull_request:
      branches: [ dev ]

  jobs:
    # ==================== JOBS: SECURITY ====================
    gitleaks:
      runs-on: ubuntu-latest
      steps:
        - name: Checkout Code
          uses: actions/checkout@v4
          with:
            fetch-depth: 0
        - name: Run Gitleaks
          uses: gitleaks/gitleaks-action@v2
          env:
            GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

    bandit:
      runs-on: ubuntu-latest
      steps:
        - name: Checkout Code
          uses: actions/checkout@v4
        - name: Set up Python
          uses: actions/setup-python@v5
          with:
            python-version: '3.10'
        - name: Install Bandit
          run: pip install bandit
        - name: Run Bandit
          run: bandit -r minisoar/

    # ==================== JOBS: LINT ====================
    lint:
      runs-on: ubuntu-latest
      steps:
        - name: Checkout Code
          uses: actions/checkout@v4
        - name: Set up Python
          uses: actions/setup-python@v5
          with:
            python-version: '3.10'
        - name: Install Ruff
          run: pip install ruff
        - name: Run Ruff Check
          run: ruff check minisoar/
        - name: Run Ruff Format Check
          run: ruff format --check minisoar/

    mypy:
      runs-on: ubuntu-latest
      steps:
        - name: Checkout Code
          uses: actions/checkout@v4
        - name: Set up Python
          uses: actions/setup-python@v5
          with:
            python-version: '3.10'
            cache: 'pip'
        - name: Install Dependencies
          run: |
            pip install -r requirements.txt
            pip install mypy types-redis types-requests types-PyYAML
        - name: Run Mypy
          run: mypy minisoar/

    # ==================== JOBS: TEST (DRAFT) ====================
    pytest-draft:
      runs-on: ubuntu-latest
      steps:
        - name: Checkout Code
          uses: actions/checkout@v4
        - name: Set up Python
          uses: actions/setup-python@v5
          with:
            python-version: '3.10'
        - name: Install Dependencies
          run: |
            pip install -r requirements.txt
            pip install pytest
        - name: Run Pytest (Draft)
          run: pytest
          continue-on-error: true
  ```

- [ ] **Step 2: Commit GitHub Action workflow**
  Run command:
  ```bash
  git add .github/workflows/ci.yml
  git commit -m "ci: add github action ci workflow for checks and linting"
  ```

---

## Chunk 2: Documentation & Changelog Update

### Task 1: Update Context.md and Changelog.md
**Files:**
- Modify: `Context.md`
- Modify: `Changelog.md`

- [ ] **Step 1: Document the pipeline enhancement in Context.md**
  Add details of the newly introduced pipeline stages under the Decision Log or in a dedicated CI/CD section.

- [ ] **Step 2: Add entry in Changelog.md**
  Add the CI/CD enhancements in `Changelog.md` with version tag and short descriptions.

- [ ] **Step 3: Commit documentation updates**
  Run command:
  ```bash
  git add Context.md Changelog.md
  git commit -m "docs: document ci/cd pipeline enhancements in context and changelog"
  ```
