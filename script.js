let usesLeft = 3;
let isPaid = false;
let currentType = 'tweet';
let paypalButton;

// Load stored state
if (localStorage.getItem('usesLeft')) usesLeft = parseInt(localStorage.getItem('usesLeft'));
if (localStorage.getItem('isPaid') === 'true') isPaid = true;

function updateCounter() {
    const counter = document.getElementById('uses-counter');
    if (counter) {
        counter.textContent = isPaid ? 'Unlimited remixes' : (usesLeft > 0 ? `${usesLeft} free remixes left` : 'Upgrade for unlimited');
    }
}

function showLogin() {
    document.getElementById('login-modal').classList.remove('hidden');
}

function closeLogin() {
    document.getElementById('login-modal').classList.add('hidden');
    document.getElementById('login-error').classList.add('hidden');
}

function showPaywall() {
    document.getElementById('paywall').classList.remove('hidden');
    if (typeof paypal !== 'undefined' && !paypalButton) {
        paypalButton = paypal.Buttons({
            style: { shape: 'pill', color: 'silver', layout: 'vertical', label: 'subscribe' },
            createSubscription: function(data, actions) {
                console.log('Creating subscription with plan_id: P-5LK680852J287884DNDUFRKA');
                return actions.subscription.create({ plan_id: 'P-5LK680852J287884DNDUFRKA' });
            },
            onApprove: async function(data, actions) {
                console.log('Subscription approved with ID:', data.subscriptionID);
                const response = await fetch('/update_subscription', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subscriptionID: data.subscriptionID })
                });
                const result = await response.json();
                if (response.ok) {
                    localStorage.setItem('isPaid', 'true');
                    isPaid = true;
                    updateCounter();
                    closePaywall();
                    alert('Welcome to Pro! You now have unlimited remixes!');
                } else {
                    alert('Error updating subscription: ' + result.error);
                }
            },
            onError: function(err) {
                console.error('PayPal Error:', err);
                alert('Error with PayPal subscription: ' + (err.message || 'Unknown error. Please try again.'));
            },
            onCancel: function(data) {
                console.log('Subscription canceled:', data);
            }
        }).render('#paypal-button-container-P-5LK680852J287884DNDUFRKA');
        console.log('PayPal button rendered');
    } else if (typeof paypal === 'undefined') {
        console.error('PayPal SDK not loaded');
        alert('PayPal is not loading. Please refresh or contact support.');
    }
}

function closePaywall() {
    document.getElementById('paywall').classList.add('hidden');
}

function selectType() {
    currentType = document.getElementById('remix-type').value;
}

async function doRemix() {
    const input = document.getElementById('input-text').value.trim();
    if (!input) {
        alert('Please paste some text first!');
        return;
    }

    const btn = document.getElementById('remix-btn');
    btn.disabled = true;
    btn.textContent = 'Remixing...';

    const prompts = {
        'tweet': 'Rewrite this as 3-5 engaging tweets:\n\n',
        'email': 'Rewrite this as a professional email:\n\n',
        'ad': 'Rewrite this as ad copy:\n\n',
        'linkedin': 'Rewrite this as a LinkedIn post:\n\n',
        'blog': 'Rewrite this as an SEO-friendly blog post with headings and structure:\n\n',
        'instagram': 'Rewrite this as an engaging Instagram caption with relevant hashtags:\n\n',
        'youtube': 'Rewrite this as a YouTube video description with timestamps and key points:\n\n',
        'press': 'Rewrite this as a professional press release:\n\n',
        'story': 'Rewrite this as an engaging narrative story:\n\n',
        'casual': 'Rewrite this in a casual tone:\n\n'
    };
    const selectedPrompt = (prompts[currentType] || prompts['tweet']) + input;

    const apiUrl = 'https://remixback.onrender.com/remixback';
    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: selectedPrompt })
        });
        const data = await response.json();
        if (response.ok) {
            document.getElementById('output-text').textContent = data.output || 'No output received';
            document.getElementById('copy-btn').classList.remove('hidden');
            if (!isPaid && data.uses_left !== 'unlimited') {
                usesLeft = data.uses_left;
                localStorage.setItem('usesLeft', usesLeft);
                updateCounter();
            }
        } else {
            if (data.error === 'Please log in to remix content') {
                showLogin();
            } else if (data.error === 'No free remixes left. Please upgrade.') {
                showPaywall();
            } else {
                alert(`Error: ${data.error}`);
            }
        }
    } catch (e) {
        console.error('Fetch Error:', e);
        alert('Failed to connect to server');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Remix It Now';
    }
}

function doCopy() {
    const text = document.getElementById('output-text').textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy to Clipboard', 2000);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Login form submission
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const errorDiv = document.getElementById('login-error');
        errorDiv.classList.add('hidden');

        try {
            const response = await fetch('/login', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            if (response.ok) {
                localStorage.setItem('isPaid', result.is_paid || false);
                localStorage.setItem('usesLeft', result.uses_left || 3);
                updateCounter();
                closeLogin();
                document.getElementById('login-btn').classList.add('hidden');
                document.getElementById('logout-btn').classList.remove('hidden');
                window.location.href = result.redirect || '/';
            } else {
                errorDiv.textContent = result.error;
                errorDiv.classList.remove('hidden');
            }
        } catch (e) {
            errorDiv.textContent = 'Failed to connect to server';
            errorDiv.classList.remove('hidden');
        }
    });

    // Contact form submission
    document.getElementById('contact-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const statusDiv = document.getElementById('contact-status');
        statusDiv.classList.remove('hidden');
        statusDiv.classList.add('text-green-500');
        statusDiv.textContent = 'Sending...';

        try {
            const response = await fetch('/contact', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            if (response.ok) {
                statusDiv.textContent = 'Message sent successfully!';
                e.target.reset();
            } else {
                statusDiv.classList.remove('text-green-500');
                statusDiv.classList.add('text-red-500');
                statusDiv.textContent = result.error || 'Failed to send message.';
            }
        } catch (e) {
            statusDiv.classList.remove('text-green-500');
            statusDiv.classList.add('text-red-500');
            statusDiv.textContent = 'Failed to connect to server.';
        }
    });

    // Event listeners for buttons
    document.getElementById('login-btn').addEventListener('click', showLogin);
    document.getElementById('close-login-btn').addEventListener('click', closeLogin);
    document.getElementById('close-paywall-btn').addEventListener('click', closePaywall);
    document.getElementById('remix-btn').addEventListener('click', doRemix);
    document.getElementById('copy-btn').addEventListener('click', doCopy);
    document.getElementById('remix-type').addEventListener('change', selectType);
    document.getElementById('logout-btn').addEventListener('click', async () => {
        const response = await fetch('/logout');
        const result = await response.json();
        if (response.ok) {
            localStorage.removeItem('isPaid');
            localStorage.removeItem('usesLeft');
            isPaid = false;
            usesLeft = 3;
            updateCounter();
            document.getElementById('login-btn').classList.remove('hidden');
            document.getElementById('logout-btn').classList.add('hidden');
            window.location.href = result.redirect;
        }
    });

    // Check session on load
    async function checkSession() {
        try {
            const response = await fetch('/check_session', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            if (response.ok && data.logged_in) {
                isPaid = data.is_paid;
                usesLeft = data.uses_left;
                localStorage.setItem('isPaid', isPaid);
                localStorage.setItem('usesLeft', usesLeft);
                updateCounter();
                document.getElementById('login-btn').classList.add('hidden');
                document.getElementById('logout-btn').classList.remove('hidden');
            } else if (!isPaid && usesLeft <= 0) {
                showPaywall();
            }
        } catch (e) {
            console.error('Session check failed:', e);
        }
    }

    checkSession();
});