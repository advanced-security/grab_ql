#!/bin/sh

if uname | grep 'Linux' 2>&1 >/dev/null ; then
    if ! patchelf; then
        echo "Installing patchelf for nuitka to work"
        if exec brew 2>&1 >/dev/null ; then
            brew install patchelf
        elif exec apt 2>&1 >/dev/null ; then
            echo "HERE"
            sudo apt -y install patchelf
        elif exec yum 2>&1 >/dev/null ; then
            sudo yum -y install patchelf
        elif exec dnf 2>&1 >/dev/null ; then
            sudo dnf -y install patchelf
        elif exec apk 2>&1 >/dev/null ; then
            sudo apk add patchelf
        fi
    fi
fi
