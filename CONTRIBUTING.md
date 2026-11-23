# Team Git Collaboration Guide

This guide defines the Git workflow for our 5-person team working on the **Bosch AI Hackathon** project.

---

## 1. One-Time Setup (New Team Members)

Run these steps once after cloning the repository:

```bash
# 1. Clone the repository
git clone https://github.com/Dharaneswara-Reddy/Bosch_AI_Hackathon.git
cd Bosch_AI_Hackathon

# 2. Configure your Git identity (use your own name and email)
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

---

## 2. Daily Workflow: Step-by-Step

### Step 1: Always Start from the Latest `main`
Never create a new branch from an outdated local `main`.

```bash
git checkout main
git pull origin main
```

---

### Step 2: Create and Switch to a New Branch
Branch naming convention: `<type>/<your-name>-<short-description>`

Types:
- `feat/`: New features / models / endpoints
- `fix/`: Bug fixes
- `docs/`: Documentation updates
- `exp/`: Quick experiments

Examples:
- `feat/raj-dataset-loader`
- `feat/ananya-yolo-model`
- `fix/rahul-null-pointer-bug`

```bash
# Create and switch to your new branch
git checkout -b feat/<your-name>-<feature-description>
```

---

### Step 3: Make Changes, Stage & Commit
Make small, atomic commits with clear messages.

```bash
# Check what files you modified or created
git status

# Stage specific files (or all changes)
git add <filename>
# or stage everything:
git add .

# Commit with a clear, descriptive message
git commit -m "feat: implement data augmentation pipeline"
```

---

### Step 4: Sync with `main` Before Pushing (Crucial!)
While you were working, teammates might have merged changes into `main`. Always pull latest `main` into your feature branch before pushing to resolve conflicts early.

```bash
# Fetch and merge latest main into your current branch
git pull origin main
```

> **If there are merge conflicts:**
> 1. Git will flag conflicted files. Open them and look for `<<<<<<<`, `=======`, `>>>>>>>`.
> 2. Resolve conflict markers.
> 3. Run `git add <resolved-file>` and `git commit -m "merge: resolve conflicts with main"`.

---

### Step 5: Push Your Branch to GitHub

```bash
# First time pushing this branch (sets upstream):
git push -u origin feat/<your-name>-<feature-description>

# Subsequent pushes on the same branch:
git push
```

---

### Step 6: Create a Pull Request (PR) on GitHub
1. Go to [Bosch_AI_Hackathon GitHub](https://github.com/Dharaneswara-Reddy/Bosch_AI_Hackathon).
2. Click **"Compare & pull request"** for your pushed branch.
3. Add a brief description of what was changed/tested.
4. Request at least 1 teammate to review and approve.
5. Merge the PR (prefer **"Squash and merge"** or **"Rebase and merge"** to keep history clean).

---

### Step 7: Clean Up After Merging
Once your PR is merged into `main` on GitHub:

```bash
# Switch back to main and update it
git checkout main
git pull origin main

# Delete your local feature branch (it is already merged)
git branch -d feat/<your-name>-<feature-description>
```

---

## 3. Golden Rules for Collaboration

1. 🚫 **NEVER push directly to `main`**: All changes go through feature branches and Pull Requests.
2. 🔒 **NEVER commit secrets, tokens, or API keys**: Store keys in `.env` (it is already listed in `.gitignore`).
3. 📦 **Do not commit massive datasets or model weights directly to Git**: Use cloud storage / shared drives / links instead. `.pt`, `.safetensors`, `.bin`, and `data/` are ignored in `.gitignore`.
4. 🔄 **Communicate what you are working on**: Avoid having two people modify the exact same files simultaneously to prevent merge conflicts.
5. 🧪 **Test before pushing**: Ensure code runs without errors before opening a PR.

---

## 4. Useful Git Commands Cheat Sheet

| Command | What it does |
|---|---|
| `git status` | Shows changed/untracked files on current branch |
| `git branch` | Lists all local branches (* marks current branch) |
| `git checkout -b <name>` | Creates and switches to a new branch |
| `git checkout <name>` | Switches to an existing branch |
| `git pull origin main` | Updates current branch with latest `main` |
| `git log --oneline -n 5` | Shows recent 5 commits cleanly |
| `git diff` | Shows unstaged line-by-line changes |
| `git stash` | Temporarily shelves uncommitted changes |
| `git stash pop` | Restores previously shelved changes |
| `git reset --soft HEAD~1` | Undoes the last commit while keeping your changes staged |
