# genpi/routes/ -- the Flask route layer (roadmap #59, Stage 9). One Blueprint per feature
# group (core, update, fuel, push); each imports the SERVICES + auth it needs from the owning
# submodules and NEVER the Flask app -- that one-way edge (app -> routes, never routes -> app)
# is exactly the cycle the blueprints exist to break. Registered onto the app in genpi/app.py.
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
