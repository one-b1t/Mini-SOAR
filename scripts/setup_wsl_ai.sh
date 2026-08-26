#!/usr/bin/env bash
set -e

mkdir -p "$HOME/.local/bin"

# Create wrapper for agy CLI in WSL
cat << 'EOF' > "$HOME/.local/bin/agy"
#!/usr/bin/env bash
exec /mnt/c/Users/bandar/AppData/Local/agy/bin/agy.exe "$@"
EOF
chmod +x "$HOME/.local/bin/agy"

# Create symlink for .gemini from Windows to WSL
if [ -L "$HOME/.gemini" ]; then
    rm -f "$HOME/.gemini"
elif [ -d "$HOME/.gemini" ]; then
    rm -rf "$HOME/.gemini"
fi
ln -s /mnt/c/Users/bandar/.gemini "$HOME/.gemini"

# Add ~/.local/bin to PATH in .bashrc if not present
if ! grep -q 'HOME/.local/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

echo "=== WSL Antigravity Setup Complete ==="
echo "1. Testing agy version:"
"$HOME/.local/bin/agy" --version || true

echo "2. Testing .gemini symlink:"
ls -ld "$HOME/.gemini"
