(() => {
  const toggle = document.querySelector('#nav-toggle');
  const nav = document.querySelector('#primary-nav');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const opened = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(opened));
    });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && nav.classList.contains('open')) {
        nav.classList.remove('open'); toggle.setAttribute('aria-expanded', 'false'); toggle.focus();
      }
    });
  }
  const langSelect = document.querySelector('#site-language');
  if (langSelect) langSelect.addEventListener('change', () => langSelect.form.requestSubmit());
  document.querySelectorAll('[data-dismiss="flash"]').forEach(button =>
    button.addEventListener('click', () => button.closest('.flash')?.remove())
  );
  document.querySelectorAll('form[data-confirm]').forEach(form => form.addEventListener('submit', event => {
    if (!confirm(form.dataset.confirm)) event.preventDefault();
  }));
  document.querySelectorAll('[data-utc]').forEach(el => {
    const date = new Date(el.dataset.utc);
    if (!Number.isNaN(date.valueOf())) {
      const preferredLocale = document.documentElement.lang === 'ko' ? 'ko-KR' : 'en-US';
      el.textContent = (preferredLocale === 'ko-KR' ? '나의 현지 시간: ' : 'Your local time: ') +
        new Intl.DateTimeFormat(preferredLocale, {dateStyle:'medium',timeStyle:'short'}).format(date);
    }
  });
  const checkGrid = document.querySelector('.check-grid');
  if (checkGrid && location.pathname === '/welcome') {
    checkGrid.addEventListener('change', e => {
      const checked = [...checkGrid.querySelectorAll('input:checked')];
      if (checked.length > 5) { e.target.checked = false; alert('최대 5개 주제를 선택할 수 있습니다.'); }
    });
  }
})();
