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
        'casual': 'Rewrite this in a casual tone:\n\n',
        'followup': 'Rewrite this as a friendly follow-up text message:\n\n',
        'apology': 'Rewrite this as a quick, sincere apology text message:\n\n',
        'reminder': 'Rewrite this as an urgent, direct reminder text message:\n\n',
        'smalltalk': 'Rewrite this as an easy, approachable small talk starter:\n\n',
        'agenda': 'Rewrite this as a focused, engaging meeting agenda teaser:\n\n',
        'interview': 'Rewrite this as a confident, concise job interview pitch:\n\n',
        'salespitch': 'Rewrite this as a persuasive, smooth sales pitch opener:\n\n',
        'thanks': 'Rewrite this as a grateful, natural casual thank-you speech:\n\n'
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
            const result = await response.json