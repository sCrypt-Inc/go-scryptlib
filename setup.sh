#!/bin/sh

COMPILER_VERSION=""
GITHUB_OWNER="sCrypt-Inc"
GITHUB_REPO="compiler_dist"
GLOB_INST_DIR="/usr/local/bin"
LOCAL_INST_DIR="$HOME/.local/bin"
BIN_NAME="scryptc"
SKIP_PROMPT=0
DISPLAY_HELP=0
UNINSTALL=0

while getopts "v:fhu" c; do
    case $c in
      v) COMPILER_VERSION="$OPTARG" ;;
      f) SKIP_PROMPT=1 ;;
      h) DISPLAY_HELP=1 ;;
      u) UNINSTALL=1 ;;
    esac
done

if [ $DISPLAY_HELP = 1 ]; then
    echo "Command options:"
    echo ""
    echo "-h Print help."
    echo "-v Install specific version compiler."
    echo "-f Skip all prompts."
    echo "-u Uninstall sCrypt."
    exit 0
fi

# If compiler version isn't explicitly specified, try to look up the latest stable rease on the web.
if [ -z $COMPILER_VERSION ]; then
    res=$(curl -s https://raw.githubusercontent.com/sCrypt-Inc/compiler_dist/master/downloadcompiler.sh | head -n 1) 
    COMPILER_VERSION="$(echo $res | cut -d'=' -f2)" 
fi
GITHUB_TAG="v$COMPILER_VERSION"

is_user_root () { [ "$(id -u)" -eq 0 ]; }

# Detect platform.
UNAME=$(uname)
if [ "$UNAME" = "Linux" -o "$UNAME" = "FreeBSD" ]; then
    URL_POSTFIX="Linux"
elif [ "$UNAME" = "Darwin" ]; then
    URL_POSTFIX="macOS"
else
    echo "OS type \"$UNAME\" not supported." && exit 2
fi

# Check if global or local install.
if ! is_user_root; then
    INSTALL_DIR="$LOCAL_INST_DIR"
else
    INSTALL_DIR="$GLOB_INST_DIR"
fi

# Create install dir if it doesn't exist yet.
mkdir -p $INSTALL_DIR

# Uninstallation procedure
if [ $UNINSTALL = 1 ]; then
    if [ -f "$INSTALL_DIR/$BIN_NAME" ]; then
        echo "You are about to uninstall the sCrypt compiler installed at: $INSTALL_DIR/$BIN_NAME"
        echo
        if [ $SKIP_PROMPT = 0 ]; then
            read -p "Proceed? [y/n] " continue < /dev/tty || exit 3
            if [ ! $continue = "y" -a ! $continue = "Y" ]; then
                exit 3
            fi
        fi
        rm $INSTALL_DIR/$BIN_NAME
        echo "The sCrypt compiler was successfully uninstalled."
        exit 0
    else
        echo "No compiler found."
        exit 4
    fi
fi

# Installation procedure
echo "You are about to download and install scryptc $GITHUB_TAG for $URL_POSTFIX."
echo
echo "The compiler will be installed to $INSTALL_DIR/$BIN_NAME. Make sure, that the containing directory is in your PATH."
if [ -f "$INSTALL_DIR/$BIN_NAME" ]; then
    echo "An existing compiler binary already exists in $INSTALL_DIR/$BIN_NAME. It will be overwritten."
fi
echo
if [ $SKIP_PROMPT = 0 ]; then
    read -p "Proceed with installation? [y/n] " continue < /dev/tty || exit 3
    if [ ! $continue = "y" -a ! $continue = "Y" ]; then
        exit 3
    fi
fi

# Remove old install if it exists.
if [ -f "$INSTALL_DIR/$BIN_NAME" ]; then
    rm $INSTALL_DIR/$BIN_NAME
fi

# Download and install the compiler.
DL_URL="https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases/download/${GITHUB_TAG}/scryptc-${COMPILER_VERSION}-${URL_POSTFIX}"
curl -L -J $DL_URL -o $INSTALL_DIR/$BIN_NAME || exit 4
chmod +x $INSTALL_DIR/$BIN_NAME || exit 5

echo
echo "The sCrypt compiler was successfully installed."
