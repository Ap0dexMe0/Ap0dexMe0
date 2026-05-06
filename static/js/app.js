/* ============================================================
   APODEXME0 // ENGINE
   ============================================================ */

/* --- UTILS --- */

function esc(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/[&<>]/g, function(m) {
    if (m === '&') return '&amp;';
    if (m === '<') return '&lt;';
    return '&gt;';
  });
}

function safeUrl(u) {
  try {
    var p = new URL(String(u), location.href);
    if (p.protocol === 'http:' || p.protocol === 'https:') return p.href;
    return '';
  } catch (e) {
    return '';
  }
}

function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

function countLines(t) {
  return t === '' ? 0 : t.split('\n').length;
}

function countWords(t) {
  var s = t.trim();
  return s ? s.split(/\s+/).length : 0;
}

/* --- THEME --- */

function getTheme() {
  var stored = localStorage.getItem('theme');
  if (stored === 'light' || stored === 'dark') return stored;
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
  return 'dark';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var meta = document.getElementById('meta-theme');
  if (meta) meta.content = theme === 'dark' ? '#09090b' : '#ffffff';
  localStorage.setItem('theme', theme);
}

function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

function initTheme() {
  applyTheme(getTheme());
  var btn = document.getElementById('theme-btn');
  if (btn) {
    btn.addEventListener('click', toggleTheme);
  }
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
      if (!localStorage.getItem('theme')) {
        applyTheme(e.matches ? 'dark' : 'light');
      }
    });
  }
}

/* --- TOAST --- */

function toast(msg) {
  var container = document.getElementById('toasts');
  var el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(function() {
    el.classList.add('hiding');
    setTimeout(function() { el.remove(); }, 150);
  }, 2200);
}

/* --- MARKDOWN --- */

var markedApi = (typeof window !== 'undefined' && window.marked)
  || (typeof marked !== 'undefined' ? marked : null);

if (markedApi && markedApi.setOptions) {
  markedApi.setOptions({ gfm: true, breaks: true });
}

function isMarkdown(ext) {
  var map = { md: 1, markdown: 1, mdown: 1, mkdn: 1, mkd: 1, mdx: 1 };
  return !!map[String(ext || '').toLowerCase()];
}

function renderMarkdown(text) {
  if (!markedApi || typeof markedApi.parse !== 'function') throw new Error('no parser');
  var html = markedApi.parse(text || '');
  if (typeof html !== 'string') return '';

  var tpl = document.createElement('template');
  tpl.innerHTML = html;

  // Strip dangerous elements
  tpl.content.querySelectorAll('script,iframe,object,embed,style,link,meta,base')
    .forEach(function(n) { n.remove(); });

  // Strip inline event handlers
  tpl.content.querySelectorAll('*').forEach(function(n) {
    Array.from(n.attributes).forEach(function(a) {
      if ((a.name || '').toLowerCase().startsWith('on')) {
        n.removeAttribute(a.name);
      }
    });
  });

  // Sanitize links
  tpl.content.querySelectorAll('a').forEach(function(a) {
    var u = safeUrl(a.getAttribute('href') || '');
    if (!u) {
      a.replaceWith(document.createTextNode(a.textContent));
      return;
    }
    a.href = u;
    a.target = '_blank';
    a.rel = 'noopener noreferrer nofollow';
  });

  // Sanitize images
  tpl.content.querySelectorAll('img').forEach(function(img) {
    var u = safeUrl(img.getAttribute('src') || '');
    if (!u) {
      img.replaceWith(document.createTextNode('[img]'));
      return;
    }
    img.src = u;
    img.loading = 'lazy';
  });

  // Add language labels to code blocks
  tpl.content.querySelectorAll('pre > code').forEach(function(code) {
    var m = (code.className || '').match(/language-([a-zA-Z0-9_-]+)/);
    if (m && code.parentElement) {
      code.parentElement.setAttribute('data-lang', String(m[1]).toUpperCase());
    }
  });

  return tpl.innerHTML;
}

function wrapTables(container) {
  if (!container) return;
  container.querySelectorAll('table').forEach(function(table) {
    if (table.parentElement && table.parentElement.classList.contains('table-wrap')) return;
    var wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });
}

/* --- SYNTAX HIGHLIGHTING --- */

function highlightCode(container) {
  if (typeof hljs === 'undefined') return;

  container.querySelectorAll('pre code').forEach(function(block) {
    var pre = block.parentElement;

    if (pre) {
      pre.classList.add('code-block');
      var langLabel = pre.getAttribute('data-lang') || 'TEXT';
      pre.setAttribute('data-lang', langLabel);

      var copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.onclick = function(e) {
        e.stopPropagation();
        navigator.clipboard.writeText(block.textContent).then(function() {
          copyBtn.textContent = 'Copied!';
          setTimeout(function() { copyBtn.textContent = 'Copy'; }, 1500);
        }).catch(function() {
          toast('Copy failed');
        });
      };
      pre.insertBefore(copyBtn, block);
    }

    var hasLang = Array.from(block.classList).some(function(c) {
      return c.indexOf('language-') === 0;
    });

    if (hasLang) {
      try {
        hljs.highlightElement(block);
      } catch (e) {
        // fallback: plain text
      }
    } else {
      try {
        var langs = [
          'asm', 'x86asm', 'nasm', 'armasm', 'cpp', 'c', 'python', 'bash',
          'powershell', 'rust', 'java', 'javascript', 'typescript',
          'json', 'xml', 'plaintext'
        ];
        var result = hljs.highlightAuto(block.textContent, langs);
        block.innerHTML = result.value;
        block.classList.add('hljs');
        if (result.language) {
          block.classList.add('language-' + result.language);
          if (pre) {
            pre.setAttribute('data-lang', result.language.toUpperCase());
          }
        }
      } catch (e) {
        // skip
      }
    }

    var lines = block.textContent.split('\n');
    if (lines.length > 1) {
      var lineNumbers = document.createElement('div');
      lineNumbers.className = 'line-numbers';
      lineNumbers.innerHTML = lines.map(function(_, i) {
        return '<span>' + (i + 1) + '</span>';
      }).join('');
      pre.insertBefore(lineNumbers, block);
      pre.classList.add('has-lines');
    }
  });
}

/* --- STATE --- */

var FS = {};
var curContent = '';
var curFile = '';
var curFilter = 'all';

/* --- FILESYSTEM --- */

async function loadFS() {
  var fs = {};
  try {
    var res = await fetch('manifest.json');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    var manifest = await res.json();

    if (manifest.directories) {
      manifest.directories.forEach(function(d) {
        if (!fs[d]) fs[d] = {};
      });
    }

    var structure = manifest.structure || {};
    for (var dir in structure) {
      if (!fs[dir]) fs[dir] = {};
      var files = structure[dir];
      if (Array.isArray(files)) {
        for (var i = 0; i < files.length; i++) {
          var fn = files[i];
          if (!fn) continue;
          try {
            var fileRes = await fetch('content/' + dir + '/' + fn);
            fs[dir][fn] = fileRes.ok ? await fileRes.text() : '';
          } catch (e) {
            fs[dir][fn] = '';
          }
        }
      }
    }
  } catch (e) {
    console.error('Failed to load filesystem:', e);
  }
  return { reverse: fs };
}

/* --- RENDER POSTS --- */

function renderPosts(filter, search) {
  var list = document.getElementById('post-list');
  var empty = document.getElementById('no-results');
  if (!FS.reverse) return;

  filter = filter || 'all';
  search = (search || '').toLowerCase().trim();

  var platforms = filter === 'all' ? Object.keys(FS.reverse) : [filter];
  var cards = [];

  platforms.forEach(function(platform) {
    var dir = FS.reverse[platform];
    if (!dir || typeof dir !== 'object') return;
    Object.keys(dir).forEach(function(filename) {
      if (typeof dir[filename] === 'object') return;
      if (search && filename.toLowerCase().indexOf(search) === -1) return;
      cards.push({
        platform: platform,
        filename: filename,
        content: dir[filename]
      });
    });
  });

  cards.sort(function(a, b) { return a.filename.localeCompare(b.filename); });

  var totalBytes = 0;

  if (!cards.length) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');

    var html = '<div class="post-grid">';

    cards.forEach(function(card) {
      var title = card.filename.replace(/\.md$/, '').replace(/[-_]/g, ' ');
      var size = formatBytes(card.content.length);
      var lineCount = countLines(card.content);
      totalBytes += card.content.length;

      html += '<div class="post-card" onclick="openViewer(\'' + esc(card.platform) + '\',\'' + esc(card.filename) + '\')">';
      html += '<div class="card-platform"><span class="post-platform" data-platform="' + esc(card.platform) + '">' + esc(card.platform) + '</span></div>';
      html += '<div class="card-body">';
      html += '<span class="card-name"><span class="post-name">' + esc(title) + '</span></span>';
      html += '<span class="card-detail"><span>' + size + '</span><span class="d">&middot;</span><span>' + lineCount + ' lines</span></span>';
      html += '</div>';
      html += '</div>';
    });

    html += '</div>';
    list.innerHTML = html;
  }

  var totalEl = document.getElementById('stat-total');
  if (totalEl) totalEl.textContent = cards.length;
  var sizeEl = document.getElementById('stat-size');
  if (sizeEl) sizeEl.textContent = formatBytes(totalBytes);
}

/* --- CATEGORY STATS --- */

function updateCategoryCounts() {
  if (!FS.reverse) return;

  var counts = { all: 0, windows: 0, linux: 0, android: 0 };

  Object.keys(FS.reverse).forEach(function(platform) {
    var dir = FS.reverse[platform];
    if (!dir || typeof dir !== 'object') return;
    var fileCount = Object.keys(dir).filter(function(fn) {
      return typeof dir[fn] === 'string';
    }).length;
    if (counts.hasOwnProperty(platform)) {
      counts[platform] = fileCount;
    }
    counts.all += fileCount;
  });

  ['all', 'windows', 'linux', 'android'].forEach(function(cat) {
    var el = document.getElementById('count-' + cat);
    if (el) el.textContent = counts[cat];
  });
}

/* --- VIEWER --- */

function openViewer(platform, filename) {
  var content = FS.reverse[platform][filename];
  if (content === undefined) { toast('Not found'); return; }

  curContent = content;
  curFile = filename;

  var ext = filename.includes('.') ? filename.split('.').pop().toLowerCase() : 'txt';
  document.getElementById('v-badge').textContent = platform.toUpperCase();
  document.getElementById('v-path').textContent = '/content/' + platform + '/' + filename;

  var rendered = document.getElementById('v-rendered');
  var rawPanel = document.getElementById('v-raw');
  var rawText = document.getElementById('raw-text');
  var rawNums = document.getElementById('raw-nums');
  var modeEl = document.getElementById('v-mode');
  var statsEl = document.getElementById('v-stats');
  var rawBtn = document.getElementById('raw-btn');

  // Render markdown
  var html = '';
  try {
    if (isMarkdown(ext)) {
      html = renderMarkdown(content);
      if (!html.trim()) throw new Error('empty');
    } else {
      html = '<pre class="whitespace-pre-wrap">' + esc(content) + '</pre>';
    }
  } catch (e) {
    html = '<p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:16px">Render failed — showing raw.</p>';
    html += '<pre class="whitespace-pre-wrap">' + esc(content) + '</pre>';
  }

  rendered.innerHTML = '<div class="prose">' + html + '</div>';
  wrapTables(rendered);
  setTimeout(function() { highlightCode(rendered); }, 10);

  // Raw view
  rawText.textContent = content;
  var lc = countLines(content);
  rawNums.innerHTML = Array.from({ length: lc }, function(_, i) {
    return '<span class="block">' + (i + 1) + '</span>';
  }).join('');

  // Stats
  var wc = countWords(content);
  statsEl.textContent = lc + ' lines \u00b7 ' + wc + ' words \u00b7 ' + formatBytes(content.length);

  // Show rendered, hide raw
  rendered.classList.remove('hidden');
  rawPanel.classList.add('hidden');
  modeEl.textContent = 'rendered';
  rawBtn.textContent = 'Raw';

  document.getElementById('viewer').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeViewer() {
  document.getElementById('viewer').classList.add('hidden');
  document.body.style.overflow = '';
  curContent = '';
  curFile = '';
}

function toggleRaw() {
  var rendered = document.getElementById('v-rendered');
  var rawPanel = document.getElementById('v-raw');
  var modeEl = document.getElementById('v-mode');
  var rawBtn = document.getElementById('raw-btn');
  var isRaw = !rawPanel.classList.contains('hidden');

  if (isRaw) {
    rawPanel.classList.add('hidden');
    rendered.classList.remove('hidden');
    modeEl.textContent = 'rendered';
    rawBtn.textContent = 'Raw';
  } else {
    rendered.classList.add('hidden');
    rawPanel.classList.remove('hidden');
    modeEl.textContent = 'raw';
    rawBtn.textContent = 'View';
  }
}

function copyFile() {
  if (!curContent) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(curContent)
        .then(function() { toast('Copied'); })
        .catch(function() { toast('Copy failed'); });
    } else {
      toast('Clipboard not available');
    }
  } catch (e) {
    toast('Copy failed');
  }
}

function dlFile() {
  if (!curContent) return;
  var blob = new Blob([curContent], { type: 'text/plain' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = curFile || 'file.txt';
  a.click();
  URL.revokeObjectURL(url);
  toast('Saved ' + curFile);
}

/* --- NAVIGATION --- */

function initNav() {
  // Filter pills
  document.querySelectorAll('.filter-pill[data-filter]').forEach(function(el) {
    el.addEventListener('click', function() {
      curFilter = this.getAttribute('data-filter');
      syncFilterPills(curFilter);
      renderPosts(curFilter, document.getElementById('search').value);
      document.querySelector('.main-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // Search with debounce
  var searchInput = document.getElementById('search');
  var searchTimer;
  searchInput.addEventListener('input', function() {
    clearTimeout(searchTimer);
    var val = this.value;
    searchTimer = setTimeout(function() {
      renderPosts(curFilter, val);
    }, 180);
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      closeViewer();
    }
    if (e.ctrlKey && e.key === 'r') {
      if (!document.getElementById('viewer').classList.contains('hidden')) {
        e.preventDefault();
        toggleRaw();
      }
    }
  });
}

function syncFilterPills(filter) {
  document.querySelectorAll('.filter-pill').forEach(function(pill) {
    pill.classList.toggle('active', pill.getAttribute('data-filter') === filter);
  });
}

/* --- INIT --- */

async function init() {
  initTheme();

  FS = await loadFS();
  updateCategoryCounts();
  renderPosts('all', '');
  initNav();
}

// Run init early to prevent flash
initTheme();
document.addEventListener('DOMContentLoaded', init);
