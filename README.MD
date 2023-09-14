# RunAsUser

## Overview

RunAsUser is a utility designed to execute command-line processes within another user's active session. It is essential that this tool is invoked with LocalSystem privileges. It proves exceptionally beneficial when you need to, for instance, access files from a network fileshare that's been mounted by another user.

For running commands as LocalSystem, you might use the `PsExec` command or establish a local service, which then calls the binary with the necessary LocalSystem privileges.

## Usage Instructions

### Display All Sessions on the Local Machine

`RunInSession list`

### Launch an Interactive PowerShell in Session 5

`RunInSession run --sid 5 powershell.exe`

By default, the initiated process will inherit RunInSession's console. Subsequently, RunInSession will disengage from this console. To direct RunInSession's error output to a file, use the `--log` option.

For instances when you prefer not to have a console attached to the new process, employ the `--no-window` parameter.

## Additional notes

Simple CMake compilation with MSVC compiler. All operational logic for the tool resides within the `main.cpp` file.

## Demos

### Taking over a AD
[<img src="https://img.youtube.com/vi/TY-wocIDCCc/hqdefault.jpg" width="600" height="300"/>](https://www.youtube.com/embed/TY-wocIDCCc)

### Opening a notepad.exe in the session of a logged-on user
[<img src="https://img.youtube.com/vi/HaF9X1aBqHI/hqdefault.jpg" width="600" height="300"/>](https://www.youtube.com/embed/HaF9X1aBqHI)

