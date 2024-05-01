# About

This project aims to understand and prototype a WebExtension (the goal) which can be installed in a users browser and enables the user a quick way to connect to an existing OBS WebRTC session.

The goal is that a user who has set up OBS to stream can easily join that live stream with their browser via either webcam or screen/tab sharing without understanding IPs and all of the other challenges.

## OBS Plugin
- The OBS plugin will be responsible for responding to mDNS queries for 'obs.local' (or, in the future, other configurable name) to let clients know how OBS can be reached.

The OBS plugin will also be responsible for configuring an output destination based on information sent to it from the browser plugin.

## Browser Plugin

The Browser Plugin will be responsible for triggering an mDNS query to find OBS (if possible?).

From this point it should allow users to navigate to a provider such as Twitch and should pull or configure the necessary settings on Twitch to enable OBS output. It will then send this configuration to OBS.

## Future Goals

The Browser Plugin should be able to configure OBS WebRTC support and allow the Browser to join an OBS session via WebRTC directly (either screen share, page share, camera share) so users do not need to jump through any other steps.
