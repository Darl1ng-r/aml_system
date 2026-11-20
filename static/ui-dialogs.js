/**
 * Sentinel Accessible Modal Dialog & Toast System (Wave 4 A11y Remediation)
 * =========================================================================
 * Replaces native blocking browser alert(), confirm(), and prompt() dialogs
 * with WCAG 2.1 AA compliant <dialog> modals using native .showModal(),
 * automatic focus trapping, Escape cancellation, and aria-live status toasts.
 */
(function () {
    'use strict';

    if (window.SentinelDialog) return;

    function ensureStyles() {
        if (document.getElementById('sentinel-dialog-styles')) return;
        const style = document.createElement('style');
        style.id = 'sentinel-dialog-styles';
        style.textContent = `
            dialog.sentinel-dialog {
                border: 1px solid #DFDDD8;
                border-radius: 14px;
                padding: 0;
                max-width: 440px;
                width: calc(100vw - 32px);
                background: #FFFFFF;
                color: #141517;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                box-shadow: 0 24px 60px rgba(20, 21, 23, 0.18);
                overflow: hidden;
            }
            dialog.sentinel-dialog::backdrop {
                background: rgba(20, 21, 23, 0.45);
                backdrop-filter: blur(4px);
            }
            .sentinel-dialog-head {
                padding: 18px 22px 12px;
                border-bottom: 1px solid #EFEFED;
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
            }
            .sentinel-dialog-title {
                margin: 0;
                font-family: 'Manrope', 'Inter', sans-serif;
                font-size: 16px;
                font-weight: 700;
                color: #141517;
                letter-spacing: -0.01em;
            }
            .sentinel-dialog-body {
                padding: 16px 22px 20px;
                font-size: 13.5px;
                line-height: 1.55;
                color: #3D414A;
            }
            .sentinel-dialog-input {
                margin-top: 12px;
                width: 100%;
                box-sizing: border-box;
                padding: 10px 12px;
                border: 1px solid #D4D2CC;
                border-radius: 8px;
                font-family: inherit;
                font-size: 13.5px;
                color: #141517;
                background: #FAF9F7;
            }
            .sentinel-dialog-input:focus {
                outline: 2px solid #141517;
                outline-offset: 1px;
                background: #FFFFFF;
            }
            .sentinel-dialog-foot {
                padding: 12px 22px 18px;
                display: flex;
                justify-content: flex-end;
                gap: 10px;
                background: #FAF9F7;
                border-top: 1px solid #EFEFED;
            }
            .sentinel-btn {
                padding: 8px 16px;
                border-radius: 8px;
                font-family: inherit;
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                border: 1px solid transparent;
                transition: background 120ms ease, opacity 120ms ease;
            }
            .sentinel-btn-secondary {
                background: #FFFFFF;
                color: #141517;
                border-color: #D4D2CC;
            }
            .sentinel-btn-secondary:hover { background: #EFEFED; }
            .sentinel-btn-primary {
                background: #141517;
                color: #FFFFFF;
            }
            .sentinel-btn-primary:hover { background: #262930; }
            .sentinel-btn-danger {
                background: #B91C1C;
                color: #FFFFFF;
            }
            .sentinel-btn-danger:hover { background: #991B1B; }
            .sentinel-toast-region {
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 9999;
                display: flex;
                flex-direction: column;
                gap: 8px;
                max-width: 380px;
            }
            .sentinel-toast {
                background: #141517;
                color: #FFFFFF;
                padding: 11px 16px;
                border-radius: 10px;
                font-size: 13px;
                line-height: 1.4;
                box-shadow: 0 12px 30px rgba(20, 21, 23, 0.22);
                border-left: 3px solid #F5A623;
            }
            .sentinel-toast[data-variant="error"] { border-left-color: #EF4444; }
            .sentinel-toast[data-variant="success"] { border-left-color: #10B981; }
        `;
        document.head.appendChild(style);
    }

    function createDialogShell(titleText, messageText) {
        ensureStyles();
        const dialog = document.createElement('dialog');
        dialog.className = 'sentinel-dialog';
        dialog.setAttribute('aria-modal', 'true');

        const titleId = `sentinel-dlg-title-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        dialog.setAttribute('aria-labelledby', titleId);

        const head = document.createElement('div');
        head.className = 'sentinel-dialog-head';
        const title = document.createElement('h2');
        title.id = titleId;
        title.className = 'sentinel-dialog-title';
        title.textContent = titleText;
        head.appendChild(title);

        const body = document.createElement('div');
        body.className = 'sentinel-dialog-body';
        const msg = document.createElement('div');
        msg.textContent = String(messageText || '');
        body.appendChild(msg);

        const foot = document.createElement('div');
        foot.className = 'sentinel-dialog-foot';

        dialog.appendChild(head);
        dialog.appendChild(body);
        dialog.appendChild(foot);
        document.body.appendChild(dialog);

        return { dialog, body, foot };
    }

    function showDialog(dialog) {
        if (typeof dialog.showModal === 'function') {
            dialog.showModal();
        } else {
            dialog.setAttribute('open', 'open');
        }
    }

    function closeAndRemove(dialog) {
        try {
            if (dialog.open && typeof dialog.close === 'function') {
                dialog.close();
            }
        } catch (_) { /* ignore */ }
        dialog.remove();
    }

    window.SentinelDialog = {
        alert(message, opts = {}) {
            return new Promise((resolve) => {
                const { dialog, foot } = createDialogShell(opts.title || 'Compliance Notice', message);
                const okBtn = document.createElement('button');
                okBtn.type = 'button';
                okBtn.className = 'sentinel-btn sentinel-btn-primary';
                okBtn.textContent = opts.confirmText || 'OK';

                const finish = () => {
                    closeAndRemove(dialog);
                    resolve();
                };
                okBtn.addEventListener('click', finish);
                dialog.addEventListener('cancel', (e) => {
                    e.preventDefault();
                    finish();
                });

                foot.appendChild(okBtn);
                showDialog(dialog);
                okBtn.focus();
            });
        },

        confirm(message, opts = {}) {
            return new Promise((resolve) => {
                const { dialog, foot } = createDialogShell(opts.title || 'Confirm Action', message);

                const cancelBtn = document.createElement('button');
                cancelBtn.type = 'button';
                cancelBtn.className = 'sentinel-btn sentinel-btn-secondary';
                cancelBtn.textContent = opts.cancelText || 'Cancel';

                const okBtn = document.createElement('button');
                okBtn.type = 'button';
                okBtn.className = opts.danger ? 'sentinel-btn sentinel-btn-danger' : 'sentinel-btn sentinel-btn-primary';
                okBtn.textContent = opts.confirmText || 'Confirm';

                const finish = (val) => {
                    closeAndRemove(dialog);
                    resolve(val);
                };

                cancelBtn.addEventListener('click', () => finish(false));
                okBtn.addEventListener('click', () => finish(true));
                dialog.addEventListener('cancel', (e) => {
                    e.preventDefault();
                    finish(false);
                });

                foot.appendChild(cancelBtn);
                foot.appendChild(okBtn);
                showDialog(dialog);
                okBtn.focus();
            });
        },

        prompt(message, defaultValue = '', opts = {}) {
            return new Promise((resolve) => {
                const { dialog, body, foot } = createDialogShell(opts.title || 'Audit Rationale Required', message);

                const input = document.createElement('input');
                input.type = 'text';
                input.className = 'sentinel-dialog-input';
                input.value = defaultValue == null ? '' : String(defaultValue);
                input.setAttribute('aria-label', String(message || 'Input'));
                body.appendChild(input);

                const cancelBtn = document.createElement('button');
                cancelBtn.type = 'button';
                cancelBtn.className = 'sentinel-btn sentinel-btn-secondary';
                cancelBtn.textContent = opts.cancelText || 'Cancel';

                const okBtn = document.createElement('button');
                okBtn.type = 'button';
                okBtn.className = 'sentinel-btn sentinel-btn-primary';
                okBtn.textContent = opts.confirmText || 'Submit';

                const finish = (val) => {
                    closeAndRemove(dialog);
                    resolve(val);
                };

                cancelBtn.addEventListener('click', () => finish(null));
                okBtn.addEventListener('click', () => finish(input.value));
                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        finish(input.value);
                    }
                });
                dialog.addEventListener('cancel', (e) => {
                    e.preventDefault();
                    finish(null);
                });

                foot.appendChild(cancelBtn);
                foot.appendChild(okBtn);
                showDialog(dialog);
                input.focus();
                input.select();
            });
        },

        toast(message, variant = 'info', durationMs = 4000) {
            ensureStyles();
            let region = document.getElementById('sentinel-toast-region');
            if (!region) {
                region = document.createElement('div');
                region.id = 'sentinel-toast-region';
                region.className = 'sentinel-toast-region';
                region.setAttribute('role', 'status');
                region.setAttribute('aria-live', 'polite');
                document.body.appendChild(region);
            }
            const item = document.createElement('div');
            item.className = 'sentinel-toast';
            item.setAttribute('data-variant', variant);
            item.textContent = String(message || '');
            region.appendChild(item);
            window.setTimeout(() => item.remove(), durationMs);
        }
    };
})();
