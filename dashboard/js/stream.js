import { MockEngine } from './engine.js';

class StreamManager {
    constructor() {
        this.engine = new MockEngine();
        this.mode = 'demo'; // 'demo' or 'live'
        this.listeners = [];
        
        this.engine.onEvent((evt) => {
            if (this.mode === 'demo') {
                this.notify(evt);
            }
        });
        
        this.engine.start();
    }

    setMode(mode) {
        this.mode = mode;
        // In live mode, we would connect to SSE /events here
        document.getElementById('mode-label').textContent = mode === 'demo' ? 'Demo Mode' : 'Live Mode';
    }

    subscribe(callback) {
        this.listeners.push(callback);
    }

    notify(event) {
        this.listeners.forEach(cb => cb(event));
    }

    triggerAttack(type) {
        if (this.mode === 'demo') this.engine.triggerAttack(type);
    }

    triggerAgentAction(action) {
        if (this.mode === 'demo') this.engine.triggerAgentAction(action);
    }

    triggerTamper(type, customData) {
        if (this.mode === 'demo') this.engine.triggerTamper(type, customData);
    }

    runVerify() {
        if (this.mode === 'demo') this.engine.runVerify();
    }

    judgeEditEntry(seq, field, newVal) {
        if (this.mode === 'demo') this.engine.judgeEditEntry(seq, field, newVal);
    }

    reset() {
        if (this.mode === 'demo') this.engine.reset();
    }
}

export const stream = new StreamManager();
