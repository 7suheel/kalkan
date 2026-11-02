# Kalkan demo for the README.
# Requires VHS (https://github.com/charmbracelet/vhs) and a curl checkout:
#   git clone https://github.com/curl/curl.git ../curl
#   vhs demo.tape
Output docs/demo.gif

Set FontSize 16
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type "uv sync -q && clear"
Enter
Sleep 3s
Show

Type "cat examples/fake-report.md"
Enter
Sleep 2s
Type "uv run kalkan triage examples/fake-report.md --repo ../curl --no-ai | head -40"
Enter
Sleep 6s
