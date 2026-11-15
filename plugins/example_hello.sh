#!/usr/bin/env bash
# shellcheck shell=bash
# Minimal example plugin demonstrating the module contract.
mod_example_hello_info() { printf -- '-|Example plugin|Demonstrates the plugin contract|ready'; }
mod_example_hello_main() { printf 'hello from example_hello plugin\n'; }
