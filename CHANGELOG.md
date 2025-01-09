# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]
- [DEPENDENCIES] Dependency updates
- [INTERNAL] Remove the use of `generic-array` crate (use the built-in version in `aes-gcm` instead)
- [INTERNAL] Optimize a salt generation and Mandelbrot encoding/decoding
- [INTERNAL] Split into multiple files
- [INTERNAL] [BREAKING] Make ChaCha20 reusuable (use `let mut laqf = ...` instead of `let laqf = ...`)

## [v0.1.1] - 1/8/2025
- [INTERNAL] Added more tests
- [INTERNAL] Added bounds checking (for empty data/salts/passwords/keypairs)
- [DEPENDENCIES] Added Dependabot for automatic updates/security checks

## [v0.1.0] - 1/6/2025
- Inital Release for v2
