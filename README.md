# root-kit

All The Tools You Need To Start Hacking!

# Installation

```bash
# Clone the repository:
$ git clone https://github.com/idobarel/root-kit.git

# Cd into the directory
$ cd root-kit

# Give permissions to install.sh:
$ chmod +x install.sh

# Run install.sh | Download the requirements and install the setup
$ ./install.sh

# Run the app:
$ sudo rootkit -h
```

# How To Use:

_The app has a lot of modules init, use -h or --help to see them all._
_For the GUI version, Use -g flag._<br>
_* pay attantion! I am not a good designer! The GUI version looks like hell! *_

# Notice!
The GUI version (used by -g flag), Using _eel_ python package for the proccessing.<br>
Because there are problems running _eel_ with _sudo_ permissions, The _install.sh_ file will<br>
use a command called setcap -> to make python3.x running with higher permissions then normal, but not with _sudo_.<br>
This is required because the main root-kit app is using _scapy_. and you need high permissions to use that.<br>
_hopefully Im Clear :)_<br>
_Some of the tools inside the program might be illegal to use with no permissions. Please, Do Not Use The App For Malicious Activities._
