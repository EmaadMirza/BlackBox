import { stream } from '../stream.js';

export function renderLedger(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>A diary nobody can <span class="keyword-red">rewrite</span>.</h1>
            <div class="red-underline"></div>
            <p>Every action cryptographically sealed, chained, and witnessed.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Component</span><span>Ledger + Witness</span></div>
            <div class="meta-row"><span>Trust level</span><span>Ledger <span style="color:var(--red);">assumed attackable</span>, Witness <span style="color:var(--white);">trusted</span></span></div>
            <div class="meta-row"><span>Read time</span><span>3 mins</span></div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                Table of Contents
                <span class="accordion-chevron">▼</span>
            </div>
            <div class="accordion-content">
                <ul>
                    <li><a href="#sealed-chain">The Sealed Chain</a></li>
                    <li><a href="#merkle-tree">Merkle Tree</a></li>
                    <li><a href="#witness">The Witness</a></li>
                    <li><a href="#heartbeat">Heartbeat Monitor</a></li>
                    <li><a href="#key-design">Key Design</a></li>
                </ul>
            </div>
        </div>

        <!-- A. Sealed Chain -->
        <div id="sealed-chain" style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">The Sealed Chain</h3>
            <div class="card" style="overflow-x: auto; white-space: nowrap; padding: 2rem;" id="chain-container">
                <!-- Blocks generated dynamically -->
            </div>
        </div>

        <!-- B. Merkle Tree -->
        <div id="merkle-tree" style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Merkle Tree</h3>
            <div class="card" style="text-align: center; padding: 2rem;">
                <svg viewBox="0 0 800 300" style="width: 100%; max-width: 800px; height: auto;">
                    <style>
                        .m-line { stroke: var(--border); stroke-width: 2; }
                        .m-node { fill: var(--surface-2); stroke: var(--border); stroke-width: 2; rx: 4; }
                        .m-root { fill: var(--bg); stroke: var(--red); stroke-width: 2; rx: 4; }
                        .m-text { fill: var(--white); font-family: var(--font-mono); font-size: 12px; text-anchor: middle; }
                        .m-sub { fill: var(--grey-400); font-family: var(--font-body); font-size: 10px; text-anchor: middle; }
                    </style>
                    
                    <!-- Lines -->
                    <path d="M 400 50 L 200 150" class="m-line" />
                    <path d="M 400 50 L 600 150" class="m-line" />
                    <path d="M 200 150 L 100 250" class="m-line" />
                    <path d="M 200 150 L 300 250" class="m-line" />
                    <path d="M 600 150 L 500 250" class="m-line" />
                    <path d="M 600 150 L 700 250" class="m-line" />

                    <!-- Nodes -->
                    <!-- Root -->
                    <rect x="340" y="30" width="120" height="40" class="m-root" />
                    <text x="400" y="48" class="m-text" fill="var(--red)">ROOT HASH</text>
                    <text x="400" y="62" class="m-sub" fill="var(--red)">Tree Size: N</text>

                    <!-- Level 1 -->
                    <rect x="150" y="130" width="100" height="40" class="m-node" />
                    <text x="200" y="155" class="m-text">Hash(0-1)</text>

                    <rect x="550" y="130" width="100" height="40" class="m-node" />
                    <text x="600" y="155" class="m-text">Hash(2-3)</text>

                    <!-- Leaves -->
                    <rect x="60" y="230" width="80" height="40" class="m-node" />
                    <text x="100" y="255" class="m-text">Entry 0</text>

                    <rect x="260" y="230" width="80" height="40" class="m-node" />
                    <text x="300" y="255" class="m-text">Entry 1</text>

                    <rect x="460" y="230" width="80" height="40" class="m-node" />
                    <text x="500" y="255" class="m-text">Entry 2</text>

                    <rect x="660" y="230" width="80" height="40" class="m-node" />
                    <text x="700" y="255" class="m-text">Entry 3</text>
                </svg>
            </div>
        </div>

        <!-- C. Witness -->
        <div id="witness" style="margin-top: 4rem;">
            <div class="card hero-card" style="text-align: center;">
                <h2 style="margin-bottom: 0.5rem;">The Witness</h2>
                <div style="font-size: 1.5rem; margin-bottom: 2rem;">Residual window: <span class="keyword-red" style="font-weight: 700;">5s</span> of entries are still UNVERIFIED</div>
                
                <div style="display: flex; justify-content: space-around; align-items: center; background: var(--bg); padding: 2rem; border-radius: 8px; border: 1px solid var(--border);">
                    <div style="border: 1px solid var(--border); padding: 1.5rem; border-radius: 8px; width: 150px;">
                        <h4 style="margin-bottom: 0.5rem;">Ledger</h4>
                        <div id="chk-send" style="font-size: 2rem; opacity: 0.2;">📤</div>
                    </div>
                    
                    <div id="chk-line" style="flex: 1; height: 2px; background: var(--border); position: relative; margin: 0 2rem;">
                        <div id="chk-dot" style="position: absolute; left: 0; top: -4px; width: 10px; height: 10px; background: var(--red); border-radius: 50%; opacity: 0;"></div>
                    </div>

                    <div style="border: 1px solid var(--border); padding: 1.5rem; border-radius: 8px; width: 150px; box-shadow: 0 0 15px rgba(255,255,255,0.1);">
                        <h4 style="margin-bottom: 0.5rem;">Witness</h4>
                        <div id="chk-recv" style="font-size: 2rem; opacity: 0.2;">✍️</div>
                    </div>
                </div>

                <div style="margin-top: 2rem; text-align: left;">
                    <h4>Recent Checkpoints</h4>
                    <div id="chk-list" style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 1rem; max-height: 150px; overflow-y: auto;">
                        <div style="color: var(--grey-400);">Waiting for checkpoint...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- D. Heartbeat -->
        <div id="heartbeat" style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Heartbeat Monitor</h3>
            <div class="card" style="background: var(--bg); overflow: hidden; position: relative; height: 120px;">
                <svg id="ecg-svg" viewBox="0 0 1000 100" style="width: 100%; height: 100%; position: absolute; left: 0; top: 0;">
                    <path id="ecg-path" d="M 0 50 L 1000 50" fill="none" stroke="var(--red)" stroke-width="2" />
                </svg>
                <div style="position: absolute; right: 1rem; top: 1rem; font-family: var(--font-mono); color: var(--grey-400);" id="hb-status">ALIVE</div>
            </div>
        </div>

        <!-- E. Key Design -->
        <div id="key-design" style="margin-top: 4rem; margin-bottom: 4rem;">
            <h3 style="margin-bottom: 1rem;">Key Design</h3>
            <div class="card" style="text-align: center;">
                <p style="color: var(--text-2); margin-bottom: 2rem;">A thief who steals today's key cannot open yesterday's entries.</p>
                <div style="display: flex; align-items: center; justify-content: center; gap: 2rem;">
                    
                    <!-- Ratchet -->
                    <div style="border: 1px solid var(--border); padding: 1.5rem; border-radius: 8px; background: var(--bg);">
                        <h4 style="margin-bottom: 1rem;">Forward-Secure Ratchet</h4>
                        <div style="display: flex; align-items: center; gap: 1rem; font-family: var(--font-mono); font-size: 0.9rem;">
                            <div style="opacity: 0.3;">CK<sub>i-1</sub></div>
                            <div>→</div>
                            <div style="color: var(--white); font-weight: bold;">CK<sub>i</sub></div>
                            <div>→</div>
                            <div style="color: var(--red);">EK<sub>i</sub></div>
                        </div>
                        <div style="margin-top: 0.5rem; font-size: 0.8rem; color: var(--grey-400);">CK_i deleted after derivation</div>
                    </div>

                    <!-- Vault -->
                    <div style="border: 1px solid var(--white); padding: 1.5rem; border-radius: 8px; background: var(--surface-2); box-shadow: 0 0 15px rgba(255,255,255,0.1);">
                        <h4 style="margin-bottom: 1rem;">Root Key Vault</h4>
                        <div style="font-size: 2rem;">🏦</div>
                        <div style="margin-top: 0.5rem; font-size: 0.8rem; color: var(--grey-400);">Offline + 3-of-5 holders</div>
                    </div>

                </div>
            </div>
        </div>

        <!-- Drawer -->
        <div id="entry-drawer" class="drawer" style="width: 350px;">
            <h3 style="margin-bottom: 1.5rem;">Sealed Entry Details</h3>
            <div style="display: flex; flex-direction: column; gap: 1rem; font-family: var(--font-mono); font-size: 0.85rem;" id="entry-fields">
                <!-- Populated dynamically -->
            </div>
            <button class="btn btn-secondary" style="margin-top: 2rem; width: 100%;" onclick="this.parentElement.classList.remove('open')">Close</button>
        </div>
    `;

    const chainContainer = container.querySelector('#chain-container');
    const chkList = container.querySelector('#chk-list');
    let seq = 1000;
    
    // Add blocks dynamically
    setInterval(() => {
        seq++;
        const block = document.createElement('div');
        block.style.cssText = 'display: inline-block; width: 100px; margin-right: 1rem; cursor: pointer; vertical-align: top; text-align: center;';
        block.innerHTML = `
            <div style="margin-bottom: 0.5rem; color: var(--grey-400); font-family: var(--font-mono); font-size: 0.8rem;">Seq ${seq}</div>
            <div class="swatch-card" style="margin: 0 auto;">
                <div class="swatch-band swatch-band-1"></div>
                <div class="swatch-band swatch-band-2"></div>
                <div class="swatch-band swatch-band-3"></div>
                <div class="swatch-band swatch-band-4"></div>
                <div class="swatch-band swatch-band-5"></div>
                <div class="swatch-band swatch-band-6"></div>
            </div>
            <div style="margin-top: 0.5rem; color: var(--white); font-size: 1.2rem;">🔒</div>
            <div style="margin-top: 0.25rem; font-family: var(--font-mono); font-size: 0.7rem; color: var(--red);">${Math.random().toString(16).substr(2, 6)}</div>
        `;
        
        block.onclick = () => {
            const drawer = container.querySelector('#entry-drawer');
            const fields = container.querySelector('#entry-fields');
            fields.innerHTML = `
                <div><strong style="color:var(--white);">Epoch:</strong> 3 <span style="cursor:help;" title="Keys rotate every epoch">ℹ️</span></div>
                <div><strong style="color:var(--white);">Seq:</strong> ${seq}</div>
                <div><strong style="color:var(--white);">Type:</strong> intent</div>
                <div><strong style="color:var(--white);">TS:</strong> ${new Date().toISOString()}</div>
                <div><strong style="color:var(--white);">CT Hash:</strong> sha256:abc... <span style="cursor:help;" title="Hash of the AES-GCM ciphertext">ℹ️</span></div>
                <div><strong style="color:var(--white);">Wrapped Key:</strong> hpke:8x... <span style="cursor:help;" title="EK_i wrapped to the root public key">ℹ️</span></div>
                <div><strong style="color:var(--white);">Chain h_i:</strong> sha256:def... <span style="cursor:help;" title="Hash chain link to previous entry">ℹ️</span></div>
                <div><strong style="color:var(--white);">Sig:</strong> ed25519:123... <span style="cursor:help;" title="Signed by current epoch key">ℹ️</span></div>
            `;
            drawer.classList.add('open');
        };

        chainContainer.appendChild(block);
        chainContainer.scrollLeft = chainContainer.scrollWidth;

        // Animate Checkpoint every 5 entries
        if(seq % 5 === 0) {
            const dot = container.querySelector('#chk-dot');
            dot.style.opacity = '1';
            dot.style.transition = 'left 1s linear';
            dot.style.left = '100%';
            
            setTimeout(() => {
                dot.style.transition = 'none';
                dot.style.left = '0';
                dot.style.opacity = '0';
                
                if (chkList.querySelector('div[style*="color: var(--grey-400)"]')) chkList.innerHTML = '';
                const chk = document.createElement('div');
                chk.style.cssText = 'display: flex; justify-content: space-between; padding: 0.5rem; background: var(--surface-2); border-radius: 4px; border: 1px solid var(--border);';
                chk.innerHTML = `
                    <span style="font-family: var(--font-mono); font-size: 0.8rem;">Size: ${seq}</span>
                    <span class="badge badge-verified">Countersigned</span>
                `;
                chkList.prepend(chk);
            }, 1000);
        }

    }, 2000);

    // Heartbeat Animation
    let xOffset = 0;
    setInterval(() => {
        xOffset += 5;
        if(xOffset > 100) xOffset = 0;
        const d = `M 0 50 L ${20 - xOffset} 50 L ${30 - xOffset} 20 L ${40 - xOffset} 80 L ${50 - xOffset} 50 L 1000 50`;
        // Hacky repeating pattern for ECG
        let pathStr = "M 0 50 ";
        for(let i=0; i<1000; i+=200) {
            pathStr += `L ${i+100} 50 L ${i+110} 20 L ${i+120} 80 L ${i+130} 50 `;
        }
        pathStr += "L 1000 50";
        container.querySelector('#ecg-path').setAttribute('d', pathStr);
    }, 100);
}
