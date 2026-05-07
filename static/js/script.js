(function() {
    const manifestUrl = 'manifest.json';
    const writeupList = document.getElementById('writeupList');
    const mainContent = document.getElementById('mainContent');
    let writeups = [];

    const escapeHtml = value => String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    const titleFromFile = file => file
        .replace(/\.md$/i, '')
        .replace(/[-_]+/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());

    const slugify = value => value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');

    const normalizeLanguage = value => {
        const language = String(value || 'text').trim().toLowerCase();
        const aliases = {
            shell: 'bash',
            sh: 'bash',
            ps: 'powershell',
            py: 'python',
            js: 'javascript',
            ts: 'typescript',
            asm: 'x86asm'
        };
        return (aliases[language] || language).replace(/[^a-z0-9_-]/g, '') || 'text';
    };

    const getHashPath = () => decodeURIComponent(window.location.hash.replace(/^#\/?/, ''));

    function inlineMarkdown(text) {
        let html = escapeHtml(text);
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
        html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
        return html;
    }

    function renderTable(lines) {
        const rows = lines.map(line => line.trim().replace(/^\||\|$/g, '').split('|').map(cell => cell.trim()));
        const header = rows[0] || [];
        const body = rows.slice(2);

        return [
            '<div class="table-scroll"><table class="hex-table markdown-table">',
            '<thead><tr>',
            header.map(cell => `<th>${inlineMarkdown(cell)}</th>`).join(''),
            '</tr></thead>',
            '<tbody>',
            body.map(row => `<tr>${row.map(cell => `<td>${inlineMarkdown(cell)}</td>`).join('')}</tr>`).join(''),
            '</tbody></table></div>'
        ].join('');
    }

    function highlightRenderedCode() {
        if (!window.hljs) return;

        document.querySelectorAll('pre code').forEach(block => {
            window.hljs.highlightElement(block);
        });
    }

    function renderMarkdown(markdown) {
        const lines = markdown.replace(/\r\n/g, '\n').split('\n');
        const blocks = [];
        let i = 0;
        let codeId = 0;

        while (i < lines.length) {
            const line = lines[i];
            const trimmed = line.trim();

            if (!trimmed) {
                i++;
                continue;
            }

            if (trimmed.startsWith('```')) {
                const language = normalizeLanguage(trimmed.slice(3).trim());
                const code = [];
                i++;
                while (i < lines.length && !lines[i].trim().startsWith('```')) {
                    code.push(lines[i]);
                    i++;
                }
                i++;
                codeId++;
                blocks.push(`
                    <div class="code-block-wrapper">
                        <div class="code-label">
                            <span><span class="lang-tag">${escapeHtml(language)}</span> — snippet</span>
                            <button class="copy-btn" data-copy-target="dynamic-code-${codeId}">📋 Copy</button>
                        </div>
                        <pre><code id="dynamic-code-${codeId}" class="language-${escapeHtml(language)}">${escapeHtml(code.join('\n'))}</code></pre>
                    </div>
                `);
                continue;
            }

            if (/^\|.+\|$/.test(trimmed) && lines[i + 1] && /^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?$/.test(lines[i + 1].trim())) {
                const tableLines = [line, lines[i + 1]];
                i += 2;
                while (i < lines.length && /^\|.+\|$/.test(lines[i].trim())) {
                    tableLines.push(lines[i]);
                    i++;
                }
                blocks.push(renderTable(tableLines));
                continue;
            }

            const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
            if (heading) {
                const level = Math.min(heading[1].length + 1, 4);
                const title = heading[2].trim();
                blocks.push(`<h${level} id="${slugify(title)}">${inlineMarkdown(title)}</h${level}>`);
                i++;
                continue;
            }

            if (/^---+$/.test(trimmed)) {
                blocks.push('<hr>');
                i++;
                continue;
            }

            if (/^>\s+/.test(trimmed)) {
                const quote = [];
                while (i < lines.length && /^>\s+/.test(lines[i].trim())) {
                    quote.push(lines[i].trim().replace(/^>\s+/, ''));
                    i++;
                }
                blocks.push(`<blockquote>${quote.map(item => `<p>${inlineMarkdown(item)}</p>`).join('')}</blockquote>`);
                continue;
            }

            if (/^[-*]\s+/.test(trimmed)) {
                const items = [];
                while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
                    items.push(lines[i].trim().replace(/^[-*]\s+/, ''));
                    i++;
                }
                blocks.push(`<ul>${items.map(item => `<li>${inlineMarkdown(item)}</li>`).join('')}</ul>`);
                continue;
            }

            if (/^\d+\.\s+/.test(trimmed)) {
                const items = [];
                while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
                    items.push(lines[i].trim().replace(/^\d+\.\s+/, ''));
                    i++;
                }
                blocks.push(`<ol>${items.map(item => `<li>${inlineMarkdown(item)}</li>`).join('')}</ol>`);
                continue;
            }

            const paragraph = [trimmed];
            i++;
            while (i < lines.length && lines[i].trim() && !/^(#{1,6})\s+/.test(lines[i].trim()) && !lines[i].trim().startsWith('```') && !/^[-*]\s+/.test(lines[i].trim()) && !/^\d+\.\s+/.test(lines[i].trim()) && !/^\|.+\|$/.test(lines[i].trim())) {
                paragraph.push(lines[i].trim());
                i++;
            }
            blocks.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
        }

        return blocks.join('\n');
    }

    function flattenManifest(manifest) {
        return Object.entries(manifest.structure || {}).flatMap(([category, files]) =>
            files
                .filter(file => /\.md$/i.test(file))
                .map(file => ({
                    category,
                    file,
                    title: titleFromFile(file),
                    path: `content/${category}/${file}`,
                    hash: `${category}/${file}`
                }))
        );
    }

    function renderSidebar() {
        const grouped = writeups.reduce((groups, item) => {
            groups[item.category] = groups[item.category] || [];
            groups[item.category].push(item);
            return groups;
        }, {});

        writeupList.innerHTML = Object.entries(grouped).map(([category, items]) => `
            <li class="writeup-category">${escapeHtml(category)}</li>
            ${items.map(item => `
                <li>
                    <a href="#${encodeURIComponent(item.hash)}" class="toc-link writeup-link" data-path="${escapeHtml(item.hash)}">
                        ${escapeHtml(item.title)}
                    </a>
                </li>
            `).join('')}
        `).join('');
    }

    function setActive(path) {
        document.querySelectorAll('.writeup-link').forEach(link => {
            link.classList.toggle('toc-active', link.dataset.path === path);
        });
    }

    function renderLoading(item) {
        mainContent.innerHTML = `
            <header class="writeup-header">
                <div class="target-icon">📄 Loading <strong>${escapeHtml(item.title)}</strong></div>
                <h1>${escapeHtml(item.title)}</h1>
                <div class="writeup-meta">
                    <span>📁 ${escapeHtml(item.category)}</span>
                    <span>🧾 ${escapeHtml(item.file)}</span>
                </div>
            </header>
            <section class="section">
                <div class="section-body">
                    <p>Loading markdown content from <code>${escapeHtml(item.path)}</code>...</p>
                </div>
            </section>
        `;
    }

    async function loadWriteup(path) {
        const item = writeups.find(entry => entry.hash === path) || writeups[0];
        if (!item) return;

        setActive(item.hash);
        renderLoading(item);

        try {
            const response = await fetch(item.path);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const markdown = await response.text();
            const firstHeading = markdown.match(/^#\s+(.+)$/m);
            const title = firstHeading ? firstHeading[1].trim() : item.title;

            document.title = `${title} — Ap0dexMe0`;
            mainContent.innerHTML = `
                <header class="writeup-header">
                    <div class="target-icon">
                        📄 Source: <strong>${escapeHtml(item.file)}</strong>
                        <span class="arch-badge">${escapeHtml(item.category)}</span>
                    </div>
                    <h1>${inlineMarkdown(title)}</h1>
                    <div class="writeup-meta">
                        <span>📁 ${escapeHtml(item.category)}</span>
                        <span>🧾 Markdown</span>
                        <span>🔗 content/${escapeHtml(item.category)}/${escapeHtml(item.file)}</span>
                    </div>
                    <div class="tag-list">
                        <span class="tag">#reverse-engineering</span>
                        <span class="tag">#${escapeHtml(item.category)}</span>
                        <span class="tag">#writeup</span>
                    </div>
                </header>
                <article class="section markdown-viewer">
                    <div class="section-body markdown-body">
                        ${renderMarkdown(markdown.replace(/^#\s+.+\n?/, ''))}
                    </div>
                </article>
                <footer class="writeup-footer">
                    <p>Ap0dexMe0 / writeups &copy; 2026 — For educational purposes only.</p>
                </footer>
            `;
            highlightRenderedCode();
        } catch (error) {
            mainContent.innerHTML = `
                <section class="section">
                    <div class="section-header">
                        <span class="section-icon exploit">!</span> Unable To Load Writeup
                    </div>
                    <div class="section-body">
                        <p>Could not load <code>${escapeHtml(item.path)}</code>.</p>
                        <div class="callout warn">
                            <strong>Tip:</strong> If you opened this page directly as a file, run it through a local server so browser fetch can read markdown files.
                        </div>
                        <pre>${escapeHtml(error.message)}</pre>
                    </div>
                </section>
            `;
        }
    }

    async function init() {
        try {
            const response = await fetch(manifestUrl);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const manifest = await response.json();
            writeups = flattenManifest(manifest);
            renderSidebar();
            await loadWriteup(getHashPath() || (writeups[0] && writeups[0].hash));
        } catch (error) {
            writeupList.innerHTML = '<li><a href="#" class="toc-link toc-active">Content unavailable</a></li>';
            mainContent.innerHTML = `
                <section class="section">
                    <div class="section-header">
                        <span class="section-icon exploit">!</span> Content Manifest Error
                    </div>
                    <div class="section-body">
                        <p>Unable to load <code>${manifestUrl}</code>.</p>
                        <pre>${escapeHtml(error.message)}</pre>
                    </div>
                </section>
            `;
        }
    }

    document.addEventListener('click', event => {
        const copyButton = event.target.closest('.copy-btn');
        if (copyButton) {
            const targetId = copyButton.getAttribute('data-copy-target') || copyButton.getAttribute('data-target');
            const codeBlock = document.getElementById(targetId);
            if (!codeBlock) return;

            navigator.clipboard.writeText(codeBlock.innerText).then(() => {
                copyButton.textContent = '✓ Copied!';
                copyButton.classList.add('copied');
                setTimeout(() => {
                    copyButton.textContent = '📋 Copy';
                    copyButton.classList.remove('copied');
                }, 1800);
            });
        }
    });

    window.addEventListener('hashchange', () => loadWriteup(getHashPath()));
    init();
})();