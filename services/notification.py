"""
services/notification.py
Notification abstraction layer (Phase E).

Design:
  - BaseNotifier: abstract interface with send(title, message, level='info').
  - TelegramNotifier: sends via Telegram Bot API (HTTP, no extra library).
  - Module-level notifier singleton: TelegramNotifier if configured, else
    NoopNotifier (app runs normally without notifications).
  - Never raises: notifier failures must not block the calling operation.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod

import requests

from config import Config

logger = logging.getLogger(__name__)

TELEGRAM_API_BASE = 'https://api.telegram.org/bot'


class BaseNotifier(ABC):
    @abstractmethod
    def send(self, title: str, message: str, level: str = 'info') -> None:
        ...


class NoopNotifier(BaseNotifier):
    def send(self, title: str, message: str, level: str = 'info') -> None:
        pass


class TelegramNotifier(BaseNotifier):
    def __init__(self, token: str, chat_id: str):
        self._api_url = f'{TELEGRAM_API_BASE}{token}/sendMessage'
        self._chat_id = chat_id

    def send(self, title: str, message: str, level: str = 'info') -> None:
        emoji = {'info': '\u2139\ufe0f', 'success': '\u2705', 'warning': '\u26a0\ufe0f', 'error': '\u274c'}
        em = emoji.get(level, '\u2139\ufe0f')
        text = f'<b>{em} {title}</b>\n{message}'

        try:
            resp = requests.post(
                self._api_url,
                json={
                    'chat_id': self._chat_id,
                    'text': text,
                    'parse_mode': 'HTML',
                    'disable_web_page_preview': True,
                },
                timeout=10,
            )
            if resp.status_code != 200:
                logger.warning(
                    '[Telegram] Gagal mengirim pesan (HTTP %s): %s',
                    resp.status_code, resp.text[:200],
                )
        except requests.exceptions.RequestException as exc:
            logger.warning('[Telegram] Gagal mengirim notifikasi: %s', exc)


def _create_notifier() -> BaseNotifier:
    token = Config.TELEGRAM_BOT_TOKEN
    chat_id = Config.TELEGRAM_CHAT_ID
    if token and chat_id:
        logger.info('[Notification] Telegram notifier aktif.')
        return TelegramNotifier(token, chat_id)
    logger.info('[Notification] Telegram tidak dikonfigurasi -- notifikasi non-aktif.')
    return NoopNotifier()


notifier = _create_notifier()


def notify(title: str, message: str, level: str = 'info') -> None:
    """Send a notification asynchronously (never blocks the caller)."""
    threading.Thread(
        target=notifier.send,
        args=(title, message, level),
        daemon=True,
    ).start()