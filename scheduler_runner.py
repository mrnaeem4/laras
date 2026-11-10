"""
scheduler_runner.py — dedicated scheduler container entrypoint (Phase G).

WHAT THIS IS
------------
The cron-only process for the `scheduler` container in docker-compose.yml.
It runs the SAME three jobs as the embedded scheduler in app.py, but
through a plain `apscheduler.schedulers.blocking.BlockingScheduler`
instead of `flask_apscheduler`. No Flask app, no HTTP server, no
blueprints, no login manager, no session backend.

WHY NOT JUST RUN create_app() AND HOLD IT OPEN
----------------------------------------------
That was the obvious approach and it is the one we deliberately rejected:

  1. It boots a whole Flask app (CSRF, Flask-Login, Flask-Session, every
     blueprint, and a MongoDB-backed session interface) purely to run
     three cron jobs. Wasted memory and a wider failure surface.
  2. flask_apscheduler ties the scheduler to Flask's lifecycle, so we
     would be fighting the abstraction (the WERKZEUG_RUN_MAIN reloader
     guard, the double-start risk, an unused HTTP port).
  3. If the web container's app code has an import-time problem, the
     scheduler would fail too — even though jobs never touch HTTP.

This runner imports only config + database + services.jobs, so a Flask
problem cannot break scheduled backups and a scheduler crash cannot take
down the web tier.

BLOCKING BEHAVIOUR
------------------
`BlockingScheduler.start()` blocks the calling thread forever. That is
exactly what a container's PID 1 wants: the process stays in the
foreground and Docker supervises it.

SHUTDOWN — AND A DEADLOCK WE HAD TO AVOID
-----------------------------------------
The obvious handler is `signal.signal(SIGTERM, lambda *_: shutdown(wait=True))`.
That is WRONG and was a real defect here: the handler runs on the MAIN
thread, which is the very thread parked inside `BlockingScheduler`'s
main loop. `shutdown(wait=True)` joins the executor threads BEFORE it
sets the stop event, so the main loop can never unwind while the handler
blocks on the join. The result is that `docker stop` hangs until Docker's
grace period expires and then SIGKILLs the process — killing an in-flight
backup exactly when we claimed to protect it.

Instead the handler only sets a flag, and the joining `shutdown(wait=True)`
runs back on the normal path once `start()` returns. The signal therefore
interrupts the loop promptly (APScheduler's main loop wakes on its stop
event because `shutdown()` sets the event) without doing blocking work
inside the handler.

SCHEDULER_ENABLED
-----------------
This process refuses to start when SCHEDULER_ENABLED=False. The flag is
still honoured so that an operator who turns the scheduler off globally
does not end up with a silently-crashing container: it exits 0 with a
clear log line instead of an exception. See config.py.
"""

from __future__ import annotations

import logging
import signal
import sys

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from config import Config
from database import init_db
from services.jobs import iter_enabled_jobs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger('scheduler_runner')


def main() -> int:
    if not Config.SCHEDULER_ENABLED:
        logger.info(
            '[Scheduler] SCHEDULER_ENABLED=False -- container scheduler '
            'tidak dijalankan (keluar dengan kode 0). Set True di container '
            'scheduler dan False di container web.'
        )
        return 0

    # Connect to MongoDB once at startup. Non-fatal by design (same
    # contract as the web app): if Mongo is down the scheduler still
    # starts, and each job reports "MongoDB tidak tersedia" via
    # notification when it fires. That behaviour is deliberate and
    # documented in database.py — do not turn it into a hard failure.
    init_db()

    scheduler = BlockingScheduler()

    registered = 0
    for job_id, func, cron_string, label in iter_enabled_jobs():
        scheduler.add_job(
            func,
            trigger=CronTrigger.from_crontab(cron_string),
            id=job_id,
            replace_existing=True,
            # Same tolerance as the embedded scheduler: a job missed
            # because the container was restarting still runs once if it
            # is within the grace window, and coalesce=True collapses a
            # backlog into a single run instead of a burst.
            misfire_grace_time=3600,
            coalesce=True,
        )
        logger.info('[Scheduler] %s dijadwalkan: %s', label, cron_string)
        registered += 1

    if registered == 0:
        logger.info(
            '[Scheduler] Tidak ada job yang aktif (semua flag *_ENABLED '
            'False) -- keluar dengan kode 0 agar container tidak di-restart '
            'terus-menerus.'
        )
        return 0

    # Signal handling. This needs care because of a real deadlock:
    #
    #   The handler runs on the MAIN thread — the same thread parked in
    #   BlockingScheduler._main_loop(). BlockingScheduler.shutdown() is
    #   implemented as `super().shutdown(wait); self._event.set()` — the
    #   stop EVENT is set only AFTER the (possibly blocking) base shutdown.
    #   With wait=True the base call joins the executor threads, so the
    #   event is never set while the handler blocks, the main loop can
    #   never unwind, and `docker stop` hangs until Docker SIGKILLs the
    #   process — killing an in-flight backup.
    #
    #   APScheduler 3.x installs NO signal handlers of its own, so there is
    #   nothing to delegate to (verified against the installed version).
    #
    # The fix: the handler calls shutdown(wait=False). That still runs
    # `self._event.set()` (so the main loop wakes and start() returns) but
    # does NOT join executor threads. The in-flight job keeps running on
    # its worker thread. We then join it on the NORMAL path, after
    # start() has returned, where blocking is safe.
    requested = {'signal': None}

    def _request_stop(signum, _frame):
        requested['signal'] = signum
        logger.info('[Scheduler] Menerima signal %s -- meminta shutdown.', signum)
        try:
            # wait=False: sets the stop event without joining. Never block
            # on a join from inside a signal handler.
            scheduler.shutdown(wait=False)
        except Exception:  # noqa: BLE001 - already-stopped races etc.
            logger.debug('[Scheduler] shutdown(wait=False) diabaikan.', exc_info=True)

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    logger.info('[Scheduler] %d job aktif -- mulai.', registered)
    try:
        scheduler.start()  # returns once the stop event is set
    except (KeyboardInterrupt, SystemExit):
        logger.info('[Scheduler] Interupsi diterima -- shut down rapi.')

    # Normal (non-handler) path: now it is safe to wait for any running job
    # to finish, so a backup in progress is never truncated.
    if requested['signal'] is not None:
        logger.info('[Scheduler] Menunggu job yang sedang berjalan selesai...')
        for executor in scheduler._executors.values():  # noqa: SLF001 - documented internal
            executor.shutdown(wait=True)

    logger.info('[Scheduler] Berhenti.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
