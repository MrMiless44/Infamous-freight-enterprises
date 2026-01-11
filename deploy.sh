#!/bin/bash
set -e

echo "🚀 Starting deployment to gh-pages..."

# Build the application
echo "📦 Building application..."
npm run build 2>&1 | tail -10

# Get current timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Deploy to gh-pages
echo "📤 Deploying to gh-pages..."
if [ -d "dist" ]; then
  git config --global user.email "237955567+MrMiless44@users.noreply.github.com"
  git config --global user.name "MR MILES"
  
  # Create gh-pages branch if it doesn't exist
  git branch -D gh-pages || true
  git worktree remove .gh-pages || true
  
  mkdir -p .gh-pages
  git worktree add -B gh-pages .gh-pages origin/gh-pages
  
  # Copy built files
  cp -r dist/* .gh-pages/
  
  # Commit and push
  cd .gh-pages
  git add -A
  git commit -m "Deploy: $TIMESTAMP" || echo "No changes to commit"
  git push origin gh-pages
  cd ..
  
  echo "✅ Deployment successful!"
else
  echo "❌ Build directory not found"
  exit 1
fi
