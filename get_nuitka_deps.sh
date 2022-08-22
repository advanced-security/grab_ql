#!/bin/sh

if uname | grep 'Linux' 2>&1 >/dev/null ; then
    install patchelf '' '' '' '' '' '' ''
    install libfuse2 fuse libfuse@2 '' fuse-libs fuse-libs fuse
fi

function install() {
    package = $1
    package_brew = $2
    pacakge_nix = $3
    package_apt = $4
    package_yum = $5
    package_dnf = $6
    package_apk = $7

    if ! command -v "${package}"; then
        echo "Installing ${package}"
        if command -v brew 2>&1 >/dev/null ; then
            if [ -n "${package_brew}"; then
                brew install "${package_brew}"
            else
                brew install "${package}"
            fi
        elif command -v nix-env 2>&1 >/dev/null ; then
            if [ -n "${package_nix}"; then
                nix-env -i "${package_nix}"
            else
                nix-env -i "${package}"
            fi
        elif command -v apt 2>&1 >/dev/null ; then
            if [ -n "${package_apt}"; then
                sudo apt -y install "${package_apt}"
            else
                sudo apt -y install "${package}"
            fi
        elif command -v yum 2>&1 >/dev/null ; then
            if [ -n "${package_yum}"; then
                sudo yum -y install "${package_yum}"
            else
                sudo yum -y install "${package}"
            fi
        elif command -v dnf 2>&1 >/dev/null ; then
            if [ -n "${package_dnf}"; then
                sudo dnf -y install "${package_dnf}"
            else
                sudo dnf -y install "${package}"
            fi
        elif command -v apk 2>&1 >/dev/null ; then
            if [ -n "${package_apk}"; then
                sudo apk add "${package_apk}"
            else
                sudo apk add "${package}"
            fi

        fi
    fi
}
