document.addEventListener('DOMContentLoaded', () => {
    const remixBtn = document.getElementById('remix-btn');
    remixBtn.addEventListener('click', () => {
        const inputText = document.getElementById('input-text').value;
        const remixType = document.getElementById('remix-type').value;
        fetch('/remix', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: inputText, remix-type: remixType })
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById('output-text').textContent = data.output || data.error;
            document.getElementById('copy-btn').classList.toggle('hidden', !data.output);
            if (data.uses_left !== undefined) {
                document.getElementById('uses-counter').textContent = `${data.uses_left} free remixes left`;
            }
        })
        .catch(error => console.error('Error:', error));
    });

    document.getElementById('copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(document.getElementById('output-text').textContent);
    });

    document.getElementById('login-btn').addEventListener('click', () => {
        document.getElementById('login-modal').classList.remove('hidden');
    });

    document.getElementById('close-login-btn').addEventListener('click', () => {
        document.getElementById('login-modal').classList.add('hidden');
    });
});