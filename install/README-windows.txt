Elenko – Windows install (no Git required)
==========================================

Prerequisites (install separately)
----------------------------------
- Node.js 20 LTS or newer (https://nodejs.org/)
- CouchDB 3.x (https://couchdb.apache.org/)

Build the release ZIP (on your dev machine)
-------------------------------------------
  powershell -ExecutionPolicy Bypass -File install\build-windows-release.ps1

Creates: dist\elenko-<version>-win-x64.zip

Install on the target PC
------------------------
1. Extract the ZIP to a folder, e.g. C:\Elenko
2. Open PowerShell in that folder (or use the full path below)
3. Run:

     powershell -ExecutionPolicy Bypass -File install\install-windows.ps1

   Optional: start at user logon via scheduled task:

     powershell -ExecutionPolicy Bypass -File install\install-windows.ps1 -RegisterStartupTask

4. Start CouchDB, then start Elenko:

     cd C:\Elenko
     npm start

5. Open http://localhost:3000/setup for first-time CouchDB setup

Upgrade
-------
1. Stop Elenko (Ctrl+C or stop the scheduled task)
2. Extract a newer ZIP over the install folder (keep .env, logs/, io/, couchdb.bootstrap.json)
3. Run:

     powershell -ExecutionPolicy Bypass -File install\upgrade-windows.ps1

Configuration
-------------
Edit .env in the install folder. See install\.env.example for available variables.
