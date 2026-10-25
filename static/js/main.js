// VoiceShield AI – Main JS
document.addEventListener('DOMContentLoaded', function () {

  // ── Flash message auto-dismiss ──────────────────────────────
  document.querySelectorAll('.alert-close').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('.alert').remove();
    });
  });
  setTimeout(() => {
    document.querySelectorAll('.alert').forEach(a => {
      a.style.transition = 'opacity 0.5s';
      a.style.opacity = '0';
      setTimeout(() => a.remove(), 500);
    });
  }, 6000);

  // ── Mobile sidebar toggle ────────────────────────────────────
  const toggle = document.getElementById('navToggle');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');

  function openSidebar() {
    sidebar && sidebar.classList.add('open');
    overlay && overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
  function closeSidebar() {
    sidebar && sidebar.classList.remove('open');
    overlay && overlay.classList.remove('open');
    document.body.style.overflow = '';
  }
  toggle && toggle.addEventListener('click', openSidebar);
  overlay && overlay.addEventListener('click', closeSidebar);

  // ── Active nav link highlight ────────────────────────────────
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && (path === href || (href !== '/' && path.startsWith(href)))) {
      link.classList.add('active');
    }
  });

  // ── File upload zone ─────────────────────────────────────────
  const zone = document.getElementById('uploadZone');
  const fileInput = document.getElementById('audioFile');
  const fileLabel = document.getElementById('fileLabel');

  if (zone && fileInput) {
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file) {
        fileInput.files = e.dataTransfer.files;
        updateFileLabel(file.name);
      }
    });
    fileInput.addEventListener('change', () => {
      if (fileInput.files[0]) updateFileLabel(fileInput.files[0].name);
    });
    function updateFileLabel(name) {
      if (fileLabel) {
        fileLabel.textContent = '✅ Selected: ' + name;
        fileLabel.style.display = 'block';
      }
    }
  }

  // ── Analyse form – loading state ─────────────────────────────
  const analyseForm = document.getElementById('analyseForm');
  const submitBtn = document.getElementById('submitBtn');
  if (analyseForm && submitBtn) {
    analyseForm.addEventListener('submit', function () {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner"></span> Analysing…';
    });
  }

  // ── Risk bar animation ───────────────────────────────────────
  document.querySelectorAll('.risk-bar-fill').forEach(bar => {
    const target = bar.dataset.score || '0';
    bar.style.width = '0%';
    requestAnimationFrame(() => {
      setTimeout(() => { bar.style.width = target + '%'; }, 100);
    });
  });

  // ── Confirm delete ───────────────────────────────────────────
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', function (e) {
      if (!confirm(this.dataset.confirm)) e.preventDefault();
    });
  });

  // ── Filter form auto-submit on select change ─────────────────
  document.querySelectorAll('.filter-auto-submit select').forEach(sel => {
    sel.addEventListener('change', () => sel.closest('form').submit());
  });

  // ── Tooltip on measurement items ─────────────────────────────
  document.querySelectorAll('[data-tooltip]').forEach(el => {
    el.title = el.dataset.tooltip;
  });
});
