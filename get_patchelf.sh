#!/bin/sh

if uname | grep 'Linux' 2>&1 >/dev/null ; then
    if ! patchelf; then
        echo "Installing patchelf for nuitka to work"
        if command -v brew 2>&1 >/dev/null ; then
            brew install patchelf
        elif command -v apt 2>&1 >/dev/null ; then
            sudo apt -y install patchelf
        elif command -v yum 2>&1 >/dev/null ; then
            sudo yum -y install patchelf
        elif command -v dnf 2>&1 >/dev/null ; then
            sudo dnf -y install patchelf
        elif command -v apk 2>&1 >/dev/null ; then
            sudo apk add patchelf
        fi
    fi
fi
