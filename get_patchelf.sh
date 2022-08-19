#!/bin/sh

if uname | grep 'Linux' ; then
    if ! patchelf; then
        echo "Installing patchelf for nuitka to work"
        if brew 2>&1 >/dev/null ; then
            brew install patchelf
        elif apt 2>&1 >/dev/null ; then
            sudo apt -y install patchelf
        elif yum 2>&1 >/dev/null ; then
            sudo yum -y install patchelf
        elif dnf 2>&1 >/dev/null ; then
            sudo dnf -y install patchelf
        elif apk 2>&1 >/dev/null ; then
            sudo apk add patchelf
        fi
    fi
fi
