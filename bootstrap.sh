#!/bin/sh

# Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift

/app/RelyingPartyServer serve --env development --hostname 0.0.0.0 --port 8080 --log debug
