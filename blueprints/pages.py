"""
blueprints/pages.py
Page-rendering routes — one route per menu item, replacing the old
single-page templates/index.html + Bootstrap-pill-tab structure with real,
separately-navigable pages (each independently debuggable, each with its
own small JS file instead of one huge dynamic_forms.js).

Each route just renders its template with `active_page` set — used by
templates/base.html to highlight the right sidebar item. The topbar title
comes from each template's own {% block topbar_title %}.

These are GET-only page routes. The actual data/API endpoints the pages'
JS calls client-side (save, list, delete, pull/push, diff, etc.) are
UNCHANGED and still live in blueprints/builder.py and blueprints/api.py —
this file only adds page routes, it doesn't touch the API surface.

Route naming deliberately avoids /tester/... for the two tester pages
(log_tester_page, pcre2_tester_page) since that prefix is already used by
blueprints/tester.py's API endpoints (POST /tester/logtest,
POST /tester/pcre2/test, POST /tester/pcre2/validate per README.md) — using
it here too would collide. /log-tester and /pcre2-tester are used instead;
this only affects the URL path, not the Python function/endpoint names, so
url_for('pages.log_tester_page') etc. in templates need no further changes
if this prefix choice is revisited later.

Register in app.py alongside the existing blueprints, e.g.:
    from blueprints.pages import pages_bp
    app.register_blueprint(pages_bp)
(no url_prefix — these are top-level page routes, not an API namespace)
"""

from __future__ import annotations

from flask import Blueprint, render_template
pages_bp = Blueprint('pages', __name__)


@pages_bp.route('/decoder')
def decoder_builder_page():
    return render_template('decoder_builder.html', title='Decoder Builder', active_page='decoder_builder')


@pages_bp.route('/rule')
def rule_builder_page():
    return render_template('rule_builder.html', title='Rule Builder', active_page='rule_builder')


@pages_bp.route('/decoders')
def decoder_list_page():
    return render_template('decoder_list.html', title='Decoder List', active_page='decoder_list')


@pages_bp.route('/rules')
def rule_list_page():
    return render_template('rule_list.html', title='Rule List', active_page='rule_list')


@pages_bp.route('/import-export')
def import_export_page():
    return render_template('import_export.html', title='Import & Export', active_page='import_export')


@pages_bp.route('/sync')
def sync_manager_page():
    return render_template('sync_manager.html', title='Sync & Manager', active_page='sync_manager')


@pages_bp.route('/log-tester')
def log_tester_page():
    return render_template('log_tester.html', title='Log Tester', active_page='log_tester')


@pages_bp.route('/pcre2-tester')
def pcre2_tester_page():
    return render_template('pcre2_tester.html', title='PCRE2 Tester', active_page='pcre2_tester')


@pages_bp.route('/tech-stack')
def tech_stack_page():
    return render_template('tech_stack.html', title='Tech Stack', active_page='tech_stack')


@pages_bp.route('/ai-proposals')
def ai_proposals_page():
    return render_template('ai_proposals.html', title='AI Proposals', active_page='ai_proposals')