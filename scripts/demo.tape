# Recorded with vhs (https://github.com/charmbracelet/vhs).
# Prefer ./scripts/record-demo.sh, which stages fixtures and sets PATH.
Output demo.gif
Set FontSize 15
Set Width 1100
Set Height 640
Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set TypingSpeed 24ms
Set Framerate 24
Set Padding 18
Set WindowBar Colorful
Set Shell bash
Hide
Type `export PATH="$LMT_BIN_DIR:$PATH"`
Enter
Type `cd "$LMT_DEMO_HOME"`
Enter
Type `export PS1='demo$ '`
Enter
Type `clear`
Enter
Show

Type `python -c 'import mcp_toolbox as m; print("local-mcp-toolbox", m.__version__)'`
Enter
Sleep 1.0s

Type `local-mcp-toolbox doctor --config restricted.yml | python -m json.tool`
Enter
Sleep 2.8s

Type `local-mcp-toolbox audit-agent-configs agent-configs/benign`
Enter
Sleep 1.6s

Type `local-mcp-toolbox audit-agent-configs agent-configs/risky --limit 5`
Enter
Sleep 5.5s

Sleep 1.2s
