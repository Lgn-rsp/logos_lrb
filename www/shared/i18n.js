(() => {
  const SUPPORTED = [
    'ru','en','de',
    'es','fr','it','pt',
    'id','vi','hi',
    'ja','ko','zh',
    'ar','cs'
  ];
  const DEFAULT = 'en';

  const DICT = {
    en: {
      'wallet.title': 'LOGOS Wallet — Secure',
      'wallet.subtitle': 'WebCrypto + IndexedDB + 16-word backup phrase',
      'wallet.login_existing': 'Log in to existing wallet',
      'wallet.create_new': 'Create a new wallet',
      'wallet.restore': 'Restore wallet from phrase'
    },
    ru: {
      'wallet.title': 'LOGOS Wallet — Кошелёк',
      'wallet.subtitle': 'WebCrypto + IndexedDB + резервная фраза из 16 слов',
      'wallet.login_existing': 'Вход в существующий кошелёк',
      'wallet.create_new': 'Создать новый кошелёк',
      'wallet.restore': 'Восстановить кошелёк по фразе'
    },
    de: {
      'wallet.title': 'LOGOS Wallet — Wallet',
      'wallet.subtitle': 'WebCrypto + IndexedDB + 16‑Wörter‑Backup',
      'wallet.login_existing': 'Bestehendes Wallet öffnen',
      'wallet.create_new': 'Neues Wallet erstellen',
      'wallet.restore': 'Wallet mit Phrase wiederherstellen'
    },

    # остальные языки пока пустые — для них будет fallback на EN
    es: {}, fr: {}, it: {}, pt: {},
    id: {}, vi: {}, hi: {},
    ja: {}, ko: {}, zh: {},
    ar: {}, cs: {}
  };

  function pickLang() {
    try {
      const stored = localStorage.getItem('logos_lang');
      if (stored && SUPPORTED.includes(stored)) return stored;
    } catch (_) {}

    const nav = (navigator.language || navigator.userLanguage || '')
      .slice(0, 2).toLowerCase();
    if (SUPPORTED.includes(nav)) return nav;
    return DEFAULT;
  }

  function applyLang(lang) {
    const dict = DICT[lang] || DICT[DEFAULT] || {};
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const value = dict[key]
        || (DICT[DEFAULT] && DICT[DEFAULT][key])
        || '';
      if (value) el.textContent = value;
    });
    document.documentElement.lang = lang;
  }

  function renderSwitcher(containerSelector) {
    const cont = document.querySelector(containerSelector);
    if (!cont) return;

    cont.classList.add('logos-lang-switcher');

    SUPPORTED.forEach(code => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = code.toUpperCase();
      btn.dataset.lang = code;
      btn.addEventListener('click', () => {
        const lang = btn.dataset.lang;
        try { localStorage.setItem('logos_lang', lang); } catch (_) {}
        applyLang(lang);
        cont.querySelectorAll('button').forEach(b =>
          b.classList.toggle('active', b === btn)
        );
      });
      cont.appendChild(btn);
    });
  }

  window.LOGOS_I18N = {
    init(containerSelector) {
      const lang = pickLang();
      try { localStorage.setItem('logos_lang', lang); } catch (_) {}
      applyLang(lang);
      if (containerSelector) renderSwitcher(containerSelector);
    }
  };
})();
