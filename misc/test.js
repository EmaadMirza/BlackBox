const { JSDOM } = require('jsdom');
const fs = require('fs');

const dom = new JSDOM(
    fs.readFileSync('./dashboard/index.html', 'utf8'),
    { 
        url: 'http://localhost:8000/dashboard/#architecture',
        runScripts: "dangerously",
        resources: "usable"
    }
);

dom.window.console.log = (...args) => console.log('BROWSER_LOG:', ...args);
dom.window.console.error = (...args) => console.error('BROWSER_ERR:', ...args);

dom.window.addEventListener('error', (event) => {
    console.error('GLOBAL_ERR:', event.error);
});

setTimeout(() => {
    console.log('App root after 2s:', dom.window.document.getElementById('app-root').innerHTML.substring(0, 200));
    process.exit(0);
}, 2000);
