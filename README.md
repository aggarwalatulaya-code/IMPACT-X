# Impact X

A free 3D browser game that teaches the 17 UN Global Goals (SDGs). You are a Runner who relights 17 beacons that the Chairman has been draining.

**Live demo:** https://impactx-game.netlify.app

## Features
- 17 goals x 3 lessons each: what is happening, how to fix it (the right way), how it helps the planet - each followed by a quiz
- Story with a one-time intro, beacons that light up as you master each goal, and a Chairman ending
- Road gates: master an SDG to earn the key to the next road
- Combat: guards scale with SDG level, skins have different weapons and abilities (F = attack, G = ability)
- 17 skins, speed boosters, checkpoints, minimap and full map, sky arena for the Chairman
- Optional accounts with cloud save (username + password, no email), Privacy Policy and Terms pages

## Tech
- Front end: one file, `index.html` (vanilla JavaScript, Three.js r128 from cdnjs, Web Audio and Web Speech for sounds and voices)
- Local saves are encrypted in the browser (SHA-256 / HMAC based)
- Back end: `netlify/functions/api.mjs` (Netlify Functions + Netlify Blobs; scrypt password hashing, HttpOnly session cookies, rate limits)

## Run locally
Open `index.html` in a browser (guest mode works with no server). For the accounts backend use the Netlify CLI: `npm install` then `netlify dev`.

## Deploy
- Static only: drag `index.html`, `privacy.html`, `terms.html` into the Deploys tab of a Netlify site
- With accounts: deploy the whole folder with the Netlify CLI or a linked GitHub repo so Netlify can install `@netlify/blobs`

## Controls
WASD / joystick = move, Space = jump, E = enter beacon or challenge Chairman, F = attack, G = skin ability, M = map

## Admin
Admin is locked unless the owner sets `ADMIN_HASH` in `index.html`. The owner password is never shared.

## Known limitations
- The game runs in the browser, so determined players can still cheat locally
- The accounts backend was tested locally with an in-memory database and has not been tested live yet
- Privacy Policy and Terms are templates and need the contact email and country filled in

## Credits
Team members: add names here

Copyright (c) 2026 Impact X. All rights reserved.
