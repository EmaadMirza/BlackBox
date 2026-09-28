import { renderHome } from './pages/home.js';
import { renderArchitecture } from './pages/architecture.js';
import { renderGateway } from './pages/gateway.js';
import { renderAgents } from './pages/agents.js';
import { renderLedger } from './pages/ledger.js';
import { renderTamper } from './pages/tamper.js';
import { renderVerify } from './pages/verify.js';
import { renderRecovery } from './pages/recovery.js';
import { renderLimits } from './pages/limits.js';
import { renderDemo } from './pages/demo.js';

let lastHash = '#home';

const routes = {
    '': renderHome,
    '#home': renderHome,
    '#architecture': renderArchitecture,
    '#gateway': renderGateway,
    '#agents': renderAgents,
    '#ledger': renderLedger,
    '#tamper': renderTamper,
    '#verify': renderVerify,
    '#recovery': renderRecovery,
    '#limits': renderLimits,
    '#demo': (root) => {
        // Restore the page we were on before clicking demo
        window.location.hash = lastHash;
        
        let overlay = document.getElementById('demo-root');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'demo-root';
            document.body.appendChild(overlay);
            renderDemo(overlay, lastHash);
        }
    }
};

let hasSeeded = false;

function renderPlaceholder(pageName) {
    const root = document.getElementById('app-root');
    root.innerHTML = `
        <div class="card hero-card">
            <h1>${pageName} <span class="keyword-red">Page</span></h1>
            <div class="red-underline"></div>
            <p>This is a placeholder for the ${pageName} page.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>
    `;
}

function handleRoute() {
    console.log("handleRoute called with hash:", window.location.hash);
    const hash = window.location.hash;
    const root = document.getElementById('app-root');
    
    // If exiting demo route, just route normally
    if (hash === '#demo') {
        routes['#demo'](root);
        return;
    }
    
    lastHash = hash || '#home';

    if(!hasSeeded) {
        hasSeeded = true;
        // The engine auto starts on import, so this is just to ensure it's loaded
    }
    
    // Update active nav links
    document.querySelectorAll('.sidebar-nav a').forEach(a => {
        a.classList.remove('active');
        if(a.getAttribute('href') === (hash || '#home')) {
            a.classList.add('active');
        }
    });

    if (routes[hash]) {
        routes[hash](root);
    } else {
        const name = hash ? hash.substring(1) : 'Unknown';
        renderPlaceholder(name.charAt(0).toUpperCase() + name.slice(1));
    }
}

// Drawer Toggle
const menuBtn = document.getElementById('menu-btn');
const drawer = document.getElementById('drawer');

menuBtn.addEventListener('click', () => {
    drawer.classList.toggle('open');
});

// Close drawer on nav click
document.querySelectorAll('.sidebar-nav a').forEach(a => {
    a.addEventListener('click', () => {
        drawer.classList.remove('open');
    });
});

window.addEventListener('hashchange', handleRoute);
window.addEventListener('DOMContentLoaded', handleRoute);
