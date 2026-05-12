import re

files = ['index.html', 'dashboard.html']
replacements = {
    '🛡️': '<i data-lucide="shield-check"></i>',
    '🔍': '<i data-lucide="search"></i>',
    '📊': '<i data-lucide="bar-chart-2"></i>',
    '📋': '<i data-lucide="clipboard-list"></i>',
    '🚨': '<i data-lucide="alert-triangle"></i>',
    '🤖': '<i data-lucide="bot"></i>',
    '🔄': '<i data-lucide="refresh-cw"></i>',
    '👨‍💼': '<i data-lucide="briefcase"></i>',
    '💻': '<i data-lucide="terminal"></i>',
    '📝': '<i data-lucide="file-text"></i>',
    '✕': '<i data-lucide="x"></i>',
    '📥': '<i data-lucide="download"></i>',
    '📤': '<i data-lucide="upload"></i>',
    '📧': '<i data-lucide="mail"></i>',
    '📱': '<i data-lucide="smartphone"></i>',
    '👤': '<i data-lucide="user"></i>',
    '🆔': '<i data-lucide="id-card"></i>',
    '💳': '<i data-lucide="credit-card"></i>',
    '🌐': '<i data-lucide="globe"></i>',
    '✅': '<i data-lucide="check-circle"></i>',
    '⚡': '<i data-lucide="zap"></i>',
    '📈': '<i data-lucide="trending-up"></i>',
    '🎯': '<i data-lucide="crosshair"></i>',
    '🕐': '<i data-lucide="clock"></i>',
    '📁': '<i data-lucide="folder"></i>',
    '📂': '<i data-lucide="folder-open"></i>',
    '🔑': '<i data-lucide="key"></i>',
    '📖': '<i data-lucide="book-open"></i>',
    '⚙️': '<i data-lucide="settings"></i>',
    '🔧': '<i data-lucide="wrench"></i>',
    '⚠️': '<i data-lucide="alert-octagon"></i>',
    '🔔': '<i data-lucide="bell"></i>',
    '⬇': '<i data-lucide="download"></i>',
    '▶': '<i data-lucide="play"></i>',
    '← ': '<i data-lucide="arrow-left"></i> ',
    ' →': ' <i data-lucide="arrow-right"></i>',
    '⭐⭐⭐⭐⭐': '<div style="display:flex;gap:4px;color:#ffd60a;"><i data-lucide="star" fill="currentColor"></i><i data-lucide="star" fill="currentColor"></i><i data-lucide="star" fill="currentColor"></i><i data-lucide="star" fill="currentColor"></i><i data-lucide="star" fill="currentColor"></i></div>',
}

for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    for emoji, lucide in replacements.items():
        content = content.replace(emoji, lucide)
    if 'unpkg.com/lucide' not in content:
        content = content.replace('<script src="app.js"></script>', '<script src="https://unpkg.com/lucide@latest"></script>\n  <script>lucide.createIcons();</script>\n  <script src="app.js"></script>')
        content = content.replace('<script src="dashboard.js"></script>', '<script src="https://unpkg.com/lucide@latest"></script>\n  <script>lucide.createIcons();</script>\n  <script src="dashboard.js"></script>')
    with open(f, 'w', encoding='utf-8') as file:
        file.write(content)
print('Done!')
