export function renderHome(container) {
    container.innerHTML = `
        <div class="card hero-card" style="position: relative; overflow: hidden; padding: 4rem; user-select: none; -webkit-user-select: none;">
            <div id="hero-canvas" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none; opacity: 0.6;"></div>
            
            <div style="position: relative; z-index: 1; max-width: 60%;">
                <h1 style="font-size: 3rem; line-height: 1.2;">When a server is compromised, the evidence is <span class="keyword-red">erased</span>. Not anymore.</h1>
                <div class="red-underline"></div>
                <p style="font-size: 1.2rem; margin-top: 1rem;">Tamper-evident logging for web apps and AI agents</p>
                
                <div style="display: flex; gap: 1.5rem; margin-top: 2.5rem; flex-wrap: wrap;">
                    <button class="btn btn-primary" style="padding: 1rem 2rem; font-size: 1.15rem;" onclick="window.location.hash='#demo'">▶ Start guided demo</button>
                    <button class="btn btn-secondary" style="padding: 1rem 2rem; font-size: 1.15rem;" onclick="window.location.hash='#architecture'">See the architecture</button>
                </div>
            </div>

            <div class="swatch-stack-container" style="position: absolute; right: 40px; top: 40px;">
                <div class="swatch-card">
                    <div class="swatch-band swatch-band-1"></div>
                    <div class="swatch-band swatch-band-2"></div>
                    <div class="swatch-band swatch-band-3"></div>
                    <div class="swatch-band swatch-band-4"></div>
                    <div class="swatch-band swatch-band-5"></div>
                    <div class="swatch-band swatch-band-6"></div>
                    <div style="font-size: 10px; text-align: center; color: var(--grey-400); padding-top: 4px;">Gateway</div>
                </div>
                <div class="swatch-card raised">
                    <div class="swatch-band swatch-band-1"></div>
                    <div class="swatch-band swatch-band-2"></div>
                    <div class="swatch-band swatch-band-3"></div>
                    <div class="swatch-band swatch-band-4"></div>
                    <div class="swatch-band swatch-band-5"></div>
                    <div class="swatch-band swatch-band-6"></div>
                    <div style="font-size: 10px; text-align: center; color: var(--grey-400); padding-top: 4px;">Ledger</div>
                </div>
                <div class="swatch-card">
                    <div class="swatch-band swatch-band-1"></div>
                    <div class="swatch-band swatch-band-2"></div>
                    <div class="swatch-band swatch-band-3"></div>
                    <div class="swatch-band swatch-band-4"></div>
                    <div class="swatch-band swatch-band-5"></div>
                    <div class="swatch-band swatch-band-6"></div>
                    <div style="font-size: 10px; text-align: center; color: var(--grey-400); padding-top: 4px;">Witness</div>
                </div>
            </div>

            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Track</span><span>Cybersecurity and Defense</span></div>
            <div class="meta-row"><span>Built for</span><span>web apps and AI agents</span></div>
            <div class="meta-row"><span>Read time</span><span>2 mins</span></div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                Table of Contents
                <span class="accordion-chevron">▼</span>
            </div>
            <div class="accordion-content">
                <ul>
                    <li><a href="#summary">AI Summary</a></li>
                    <li><a href="#architecture">Architecture</a></li>
                    <li><a href="#phases">Before / During / After Attack</a></li>
                    <li><a href="#features">Not just logs</a></li>
                    <li><a href="#limits">What BlackBox does NOT claim</a></li>
                </ul>
            </div>
        </div>

        <div id="summary" class="ai-summary">
            <h3>AI Summary</h3>
            <span class="badge badge-unverified">Summary, not evidence</span>
            <p>BlackBox is a gateway that intercepts all traffic to your app. It writes a cryptographically sealed, tamper-evident diary entry for every request. If an attacker breaches the server and alters logs, a separate Witness detects the change immediately. This guarantees that you always have an intact record of how they got in and what they touched.</p>
        </div>



        <div id="phases" style="margin-top: 4rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem;">
            <div class="card">
                <h4 style="margin-bottom:1rem;">Before attack</h4>
                <p>Verifies request signatures, enforces rules, drops known bad patterns.</p>
            </div>
            <div class="card">
                <h4 style="margin-bottom:1rem;">During attack</h4>
                <p>Auto-bans attackers, quarantines routes, halts sensitive AI actions.</p>
            </div>
            <div class="card">
                <h4 style="margin-bottom:1rem;">After attack</h4>
                <p>Generates blast-radius reports, highlights missing logs, replays good writes.</p>
            </div>
        </div>

        <div id="features" style="margin-top: 4rem;">
            <h3>Not just logs</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-top: 1.5rem;">
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Verified requests</h4><p>Signatures on everything.</p></div>
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Sealed log</h4><p>Forward-secure Merkle chains.</p></div>
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Independent witness</h4><p>Completeness guaranteed.</p></div>
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Recovery</h4><p>Write-journal replay.</p></div>
            </div>
        </div>



        <div style="margin-top: 4rem; display:flex; gap: 2rem; border-top: 1px solid var(--border); padding-top: 2rem;">
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-req">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Requests seen</div>
            </div>
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-blk">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Attacks blocked</div>
            </div>
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-sl">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Entries sealed</div>
            </div>
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-chk">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Checkpoints witnessed</div>
            </div>
        </div>
    `;

    // Hook up some dummy counter increments just to feel alive
    let req=0, blk=0, sl=0, chk=0;
    const counterInterval = setInterval(() => {
        req += Math.floor(Math.random() * 5);
        if(Math.random()>0.8) blk++;
        sl = req;
        if(req % 10 === 0) chk++;
        
        const elReq = document.getElementById('counter-req');
        if(elReq) {
            elReq.innerText = req;
            document.getElementById('counter-blk').innerText = blk;
            document.getElementById('counter-sl').innerText = sl;
            document.getElementById('counter-chk').innerText = chk;
        } else {
            // Element gone — user navigated away, clean up
            clearInterval(counterInterval);
        }
    }, 2000);

    // Initialize Three.js Animation
    setTimeout(() => {
        const canvasContainer = document.getElementById('hero-canvas');
        if (!canvasContainer || typeof THREE === 'undefined') return;

        // Clean up previous instance if exists (useful for SPA navigation)
        canvasContainer.innerHTML = '';

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, canvasContainer.clientWidth / canvasContainer.clientHeight, 0.1, 1000);
        
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(canvasContainer.clientWidth, canvasContainer.clientHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        canvasContainer.appendChild(renderer.domElement);

        // Create a 3D geometric network/cube structure representing the "BlackBox"
        const geometry = new THREE.IcosahedronGeometry(2, 1);
        const material = new THREE.MeshBasicMaterial({ 
            color: 0xff3c3c, // Crimson red
            wireframe: true,
            transparent: true,
            opacity: 0.3
        });
        
        const sphere = new THREE.Mesh(geometry, material);
        
        // Inner solid core
        const innerGeo = new THREE.IcosahedronGeometry(1.5, 0);
        const innerMat = new THREE.MeshBasicMaterial({
            color: 0x0a0a0b, // Background dark
            transparent: true,
            opacity: 0.9
        });
        const innerSphere = new THREE.Mesh(innerGeo, innerMat);
        
        const group = new THREE.Group();
        group.add(sphere);
        group.add(innerSphere);
        
        // Position it on the right side of the hero card
        group.position.x = 4;
        scene.add(group);

        camera.position.z = 5;

        // Floating particles
        const particlesGeo = new THREE.BufferGeometry();
        const particlesCount = 150;
        const posArray = new Float32Array(particlesCount * 3);
        
        for(let i = 0; i < particlesCount * 3; i++) {
            posArray[i] = (Math.random() - 0.5) * 15;
        }
        
        particlesGeo.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
        const particlesMat = new THREE.PointsMaterial({
            size: 0.05,
            color: 0xff3c3c,
            transparent: true,
            opacity: 0.5
        });
        
        const particlesMesh = new THREE.Points(particlesGeo, particlesMat);
        scene.add(particlesMesh);

        let mouseX = 0;
        let mouseY = 0;
        
        // Track mouse for subtle parallax
        const handleMouseMove = (event) => {
            mouseX = (event.clientX / window.innerWidth) * 2 - 1;
            mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
        };
        window.addEventListener('mousemove', handleMouseMove);

        let animationFrameId;
        const animate = function () {
            animationFrameId = requestAnimationFrame(animate);

            // Rotate the core object
            group.rotation.x += 0.002;
            group.rotation.y += 0.003;
            
            // Subtle parallax based on mouse
            group.position.x += (4 + mouseX * 0.8 - group.position.x) * 0.15;
            group.position.y += (mouseY * 0.8 - group.position.y) * 0.15;
            
            // Rotate particles slowly
            particlesMesh.rotation.y -= 0.001;

            renderer.render(scene, camera);
        };

        animate();
        
        // Handle resize
        const handleResize = () => {
            if(!canvasContainer) return;
            camera.aspect = canvasContainer.clientWidth / canvasContainer.clientHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(canvasContainer.clientWidth, canvasContainer.clientHeight);
        };
        window.addEventListener('resize', handleResize);
        
        // Cleanup when leaving page (optional but good practice)
        canvasContainer.addEventListener('DOMNodeRemoved', () => {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('resize', handleResize);
            cancelAnimationFrame(animationFrameId);
            renderer.dispose();
        });

    }, 100);
}
