document.addEventListener('DOMContentLoaded', () => {
    console.log('PhishGuard loaded');

    // Future Heuristic Engine Logic triggers can go here
    const scanBtn = document.querySelector('.scan-btn');
    const urlInput = document.querySelector('.input-field');

    if (scanBtn && urlInput) {
        scanBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (url) {
                console.log('Scanning URL:', url);
                // Placeholder for heuristic scan trigger
                alert(`Scanning: ${url} (Logic not implemented yet)`);
            } else {
                urlInput.focus();
                urlInput.classList.add('shake');
                setTimeout(() => urlInput.classList.remove('shake'), 500);
            }
        });
    }
});
