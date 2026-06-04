const result = document.getElementById('result');
const address = document.getElementById('address');
const claimBtn = document.getElementById('claimBtn');
const themeBtn = document.getElementById('themeBtn');

function apiBase() {
  if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') return 'http://127.0.0.1:8010';
  return location.origin;
}

function print(obj) {
  result.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

claimBtn.onclick = async () => {
  const a = address.value.trim();
  if (!a.startsWith('@rafa.')) return print('Invalid address. Rafaela addresses must start with @rafa.');
  claimBtn.disabled = true;
  print('Claiming...');
  try {
    const res = await fetch(apiBase() + '/faucet/claim', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({address: a})
    });
    const json = await res.json();
    print(json);
  } catch (err) {
    print('Network error: ' + err.message);
  } finally {
    claimBtn.disabled = false;
  }
};

themeBtn.onclick = () => {
  const html = document.documentElement;
  const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
  html.dataset.theme = next;
  themeBtn.textContent = next === 'dark' ? 'Light' : 'Dark';
};
