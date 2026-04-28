/**
 * WiFi Captive Portal — Frontend JavaScript
 * Admin panel: AJAX actions for users, devices, and federation nodes.
 * Portal: password toggle, registration validation.
 */

/* ── Password toggle ─────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.toggle-pwd').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.target);
      if (!input) return;
      const isText = input.type === 'text';
      input.type = isText ? 'password' : 'text';
      btn.querySelector('i').className = `bi bi-eye${isText ? '' : '-slash'}`;
    });
  });

  /* Register form — confirm password validation */
  const form = document.getElementById('registerForm');
  if (form) {
    form.addEventListener('submit', e => {
      const pw = document.getElementById('reg-password');
      const confirm = document.getElementById('reg-confirm');
      if (pw && confirm && pw.value !== confirm.value) {
        e.preventDefault();
        confirm.classList.add('is-invalid');
        confirm.focus();
      } else if (confirm) {
        confirm.classList.remove('is-invalid');
      }
    });
    const confirm = document.getElementById('reg-confirm');
    if (confirm) {
      confirm.addEventListener('input', () => confirm.classList.remove('is-invalid'));
    }
  }
});

/* ── Admin helpers ───────────────────────────────────────────────────────── */

/**
 * POST JSON to a URL and return the parsed response.
 * Shows a toast-like alert on error.
 */
async function adminPost(url, body = {}) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  if (!resp.ok) {
    alert(`Error: ${data.error || resp.statusText}`);
    return null;
  }
  return data;
}

/* ── Users ───────────────────────────────────────────────────────────────── */

async function toggleUser(userId, currentlyActive) {
  const data = await adminPost(`/admin/users/${userId}/toggle`);
  if (!data) return;
  // Reload to reflect new state
  location.reload();
}

async function deleteUser(userId, username) {
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  const data = await adminPost(`/admin/users/${userId}/delete`);
  if (!data) return;
  const row = document.getElementById(`user-row-${userId}`);
  if (row) row.remove();
}

/* ── Devices ─────────────────────────────────────────────────────────────── */

async function authorizeDevice(mac) {
  const enc = encodeURIComponent(mac);
  const data = await adminPost(`/admin/devices/${enc}/authorize`);
  if (data) location.reload();
}

async function revokeDevice(mac) {
  if (!confirm(`Revoke access for device ${mac}?`)) return;
  const enc = encodeURIComponent(mac);
  const data = await adminPost(`/admin/devices/${enc}/revoke`);
  if (data) location.reload();
}

async function deleteDevice(mac) {
  if (!confirm(`Remove device ${mac} from the registry?`)) return;
  const enc = encodeURIComponent(mac);
  const data = await adminPost(`/admin/devices/${enc}/delete`);
  if (data) location.reload();
}

/* ── Federation Nodes ────────────────────────────────────────────────────── */

async function toggleNodeTrust(nodeId, currentlyTrusted) {
  const enc = encodeURIComponent(nodeId);
  const data = await adminPost(`/admin/nodes/${enc}/trust`);
  if (data) location.reload();
}

async function deleteNode(nodeId) {
  if (!confirm(`Remove federation node "${nodeId}"?`)) return;
  const enc = encodeURIComponent(nodeId);
  const data = await adminPost(`/admin/nodes/${enc}/delete`);
  if (data) location.reload();
}

async function addNode() {
  const nodeId   = document.getElementById('new-node-id').value.trim();
  const hostname = document.getElementById('new-node-hostname').value.trim();
  const ip       = document.getElementById('new-node-ip').value.trim();
  const port     = parseInt(document.getElementById('new-node-port').value, 10) || 5000;
  const secret   = document.getElementById('new-node-secret').value.trim();

  if (!nodeId || !hostname || !ip) {
    alert('Node ID, hostname, and IP address are required.');
    return;
  }

  const data = await adminPost('/admin/nodes', {
    node_id: nodeId, hostname, ip_address: ip, port, shared_secret: secret,
  });
  if (data) {
    bootstrap.Modal.getInstance(document.getElementById('addNodeModal')).hide();
    location.reload();
  }
}

/* ── Logical Graph ───────────────────────────────────────────────────────── */

function renderLogicalGraph(payload) {
  const panel = document.getElementById('logical-graph-panel');
  if (!panel) return;

  const graph = payload.graph || { nodes: [], edges: [] };
  const summary = payload.summary || {};

  const nodeChips = (graph.nodes || []).map(node => {
    const state = node.is_local ? 'Local' : (node.is_trusted ? 'Trusted' : 'Observed');
    const badgeClass = node.is_local ? 'bg-primary' : (node.is_trusted ? 'bg-success' : 'bg-secondary');
    return `<span class="badge ${badgeClass} me-1 mb-1">${node.id} • ${state}</span>`;
  }).join('');

  const edgeRows = (graph.edges || []).map(edge => {
    const score = typeof edge.score === 'number' ? edge.score.toFixed(3) : '-';
    return `<tr>
      <td>${edge.source}</td>
      <td>${edge.target}</td>
      <td>${edge.type}</td>
      <td>${edge.status || '-'}</td>
      <td>${score}</td>
    </tr>`;
  }).join('');

  panel.innerHTML = `
    <div class="mb-2">
      <span class="me-3"><strong>Nodes:</strong> ${summary.node_count || 0}</span>
      <span class="me-3"><strong>Edges:</strong> ${summary.edge_count || 0}</span>
      <span><strong>Trusted:</strong> ${summary.trusted_count || 0}</span>
    </div>
    <div class="mb-2">${nodeChips || '<span class="text-muted">No nodes</span>'}</div>
    <div class="table-responsive">
      <table class="table table-sm align-middle mb-0">
        <thead>
          <tr><th>Source</th><th>Target</th><th>Type</th><th>Status</th><th>Score</th></tr>
        </thead>
        <tbody>
          ${edgeRows || '<tr><td colspan="5" class="text-muted">No edges</td></tr>'}
        </tbody>
      </table>
    </div>
  `;
}

async function loadLogicalFederationGraph() {
  const panel = document.getElementById('logical-graph-panel');
  if (!panel) return;

  panel.textContent = 'Loading graph...';
  try {
    const resp = await fetch('/admin/graph');
    const data = await resp.json();
    if (!resp.ok) {
      panel.textContent = `Graph load failed: ${data.error || resp.statusText}`;
      return;
    }
    renderLogicalGraph(data);
  } catch (_err) {
    panel.textContent = 'Graph load failed due to network/server error.';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('logical-graph-panel')) {
    loadLogicalFederationGraph();
  }
});
