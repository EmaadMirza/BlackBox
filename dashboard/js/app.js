import { animate } from "https://cdn.jsdelivr.net/npm/motion@11.11.13/+esm";
import { renderHome } from './pages/home.js?v=16';
import { renderArchitecture } from './pages/architecture.js?v=16';
import { renderGateway } from './pages/gateway.js?v=16';
import { renderAgents } from './pages/agents.js?v=16';
import { renderLedger } from './pages/ledger.js?v=16';
import { renderTamper } from './pages/tamper.js?v=16';
import { renderVerify } from './pages/verify.js?v=16';
import { renderRecovery } from './pages/recovery.js?v=16';
import { renderLimits } from './pages/limits.js?v=16';
import { renderDemo } from './pages/demo.js?v=16';

// Disable automatic browser scroll restoration on refresh
if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
}

// Continuous rotation for the logo cube
animate(".logo-cube", { rotateX: [0, 360], rotateY: [0, 360] }, { duration: 8, repeat: Infinity, ease: "linear" });

let lastHash = '#home';
let isInitialLoad = true;

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
    
    const prevHash = lastHash;
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
        // If we are actually changing pages OR it's the initial load, scroll to top
        if (prevHash !== hash || isInitialLoad) {
            window.scrollTo(0, 0);
        }
        routes[hash](root);
    } else {
        const name = hash ? hash.substring(1) : 'Unknown';
        window.scrollTo(0, 0);
        renderPlaceholder(name.charAt(0).toUpperCase() + name.slice(1));
    }
    
    isInitialLoad = false;
    
    // Intercept internal page anchor links (TOC) so they don't break the SPA routing
    root.querySelectorAll('a[href^="#"]').forEach(a => {
        a.addEventListener('click', (e) => {
            const href = a.getAttribute('href');
            // If it's a registered page route (e.g. #architecture), let the browser handle it
            if (routes[href]) return;
            
            // Otherwise, it's a TOC link for the current page
            e.preventDefault();
            const targetId = href.substring(1);
            const targetEl = document.getElementById(targetId);
            if (targetEl) {
                const topbar = document.querySelector('.topbar');
                const offset = topbar ? topbar.offsetHeight + 20 : 80;
                const y = targetEl.getBoundingClientRect().top + window.scrollY - offset;
                window.scrollTo({ top: y, behavior: 'smooth' });
            }
        });
    });
}

// Drawer Toggle & Desktop Sidebar Logic
const menuBtn = document.getElementById('menu-btn');
const drawer = document.getElementById('drawer');
const sidebarDesktop = document.querySelector('.sidebar-desktop');
let hideTimeout;

// Mobile toggle & Desktop Pin
menuBtn.addEventListener('click', () => {
    if (window.innerWidth >= 768) {
        document.body.classList.toggle('sidebar-pinned');
    } else {
        drawer.classList.toggle('open');
    }
});

// Desktop Hover (Float over)
const handleMouseEnter = () => {
    if (window.innerWidth >= 768) {
        clearTimeout(hideTimeout);
        document.body.classList.add('sidebar-hovered');
    }
};

const handleMouseLeave = () => {
    if (window.innerWidth >= 768) {
        hideTimeout = setTimeout(() => {
            document.body.classList.remove('sidebar-hovered');
        }, 150);
    }
};

menuBtn.addEventListener('mouseenter', handleMouseEnter);
menuBtn.addEventListener('mouseleave', handleMouseLeave);
if (sidebarDesktop) {
    sidebarDesktop.addEventListener('mouseenter', handleMouseEnter);
    sidebarDesktop.addEventListener('mouseleave', handleMouseLeave);
}

// Close drawer/sidebar on nav click
document.querySelectorAll('.sidebar-nav a').forEach(a => {
    a.addEventListener('click', () => {
        drawer.classList.remove('open');
        // Unpin on navigation to keep UI clean, optional:
        // document.body.classList.remove('sidebar-pinned');
    });
});

window.addEventListener('hashchange', handleRoute);
window.addEventListener('DOMContentLoaded', () => {
    handleRoute();
    initGlobalBackground();
});

// Global 3D Background
function initGlobalBackground() {
    const canvas = document.getElementById('global-bg');
    if (!canvas || !window.THREE) return;

    const scene = new THREE.Scene();
    
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 20;

    const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(window.devicePixelRatio);

    const group = new THREE.Group();
    scene.add(group);

    // Prominent deep-red wireframe sphere in the background
    const geo = new THREE.IcosahedronGeometry(15, 2);
    const mat = new THREE.MeshBasicMaterial({
        color: 0xE4002B, // bright crimson
        wireframe: true,
        transparent: true,
        opacity: 0.15
    });
    const sphere = new THREE.Mesh(geo, mat);
    group.add(sphere);

    // Floating particles
    const pGeo = new THREE.BufferGeometry();
    const pCount = 500;
    const pArr = new Float32Array(pCount * 3);
    for(let i=0; i<pCount*3; i++) {
        pArr[i] = (Math.random() - 0.5) * 60;
    }
    pGeo.setAttribute('position', new THREE.BufferAttribute(pArr, 3));
    const pMat = new THREE.PointsMaterial({
        size: 0.15,
        color: 0xFF5C5C, // intense bright red
        transparent: true,
        opacity: 0.6
    });
    const particles = new THREE.Points(pGeo, pMat);
    group.add(particles);

    // Mouse tracking for parallax
    let mouseX = 0;
    let mouseY = 0;
    window.addEventListener('mousemove', (e) => {
        mouseX = (e.clientX / window.innerWidth) * 2 - 1;
        mouseY = -(e.clientY / window.innerHeight) * 2 + 1;
    });

    const animate = () => {
        requestAnimationFrame(animate);
        
        sphere.rotation.x += 0.0005;
        sphere.rotation.y += 0.001;
        particles.rotation.y -= 0.0002;
        particles.rotation.x += 0.0001;

        group.position.x += (mouseX * 1.5 - group.position.x) * 0.1;
        group.position.y += (mouseY * 1.5 - group.position.y) * 0.1;

        renderer.render(scene, camera);
    };
    animate();

    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}
