# Kalkan demo for the README.
# Requires VHS (https://github.com/charmbracelet/vhs) and a curl checkout:
#   git clone https://github.com/curl/curl.git ../curl
#   vhs demo.tape
Output docs/demo.gif

Set FontSize 15
Set Width 1400
Set Height 760
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "uv sync -q && clear"
Enter
Sleep 3s
Show

Type "cat examples/fake-report.md"
Enter
Sleep 2s
Type "uv run kalkan check examples/fake-report.md --repo ../curl"
Enter
Sleep 3s
Type "uv run kalkan triage examples/fake-report.md --repo ../curl --no-ai 2>/dev/null | sed -n 3p"
Enter
Sleep 6s
