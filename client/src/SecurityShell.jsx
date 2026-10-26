import { useEffect, useState } from 'react';

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed. Please sign in again.');
  return data;
}

export default function SecurityShell({ children }) {
  const [state, setState] = useState({ loading: true, user: null });
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const session = await api('/api/session');
        if (!session.user) { if (active) setState({ ...session, loading: false }); return; }
        const [progress, security] = await Promise.all([api('/api/classroom/progress'), api('/api/classroom/security')]);
        if (active) setState({ ...session, ...progress, security, loading: false });
      } catch { if (active) { setError('The classroom backend is unavailable or not configured yet. Please contact the project administrator.'); setState({ loading: false, user: null }); } }
    }
    load();
    return () => { active = false; };
  }, []);

  async function save(completed, tasks) {
    if (saving) return;
    setSaving(true); setError('');
    try {
      const result = await api('/api/classroom/progress', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, body: JSON.stringify({ completed, tasks }) });
      setState(previous => ({ ...previous, ...result }));
    } catch (reason) { setError(reason.message); }
    finally { setSaving(false); }
  }

  if (state.loading) return <main className="min-h-screen bg-[#f8f5ff] p-12 text-[#292238]" role="status">Opening your classroom…</main>;
  if (!state.user) return <main className="flex min-h-screen items-center justify-center bg-[#f8f5ff] p-6 text-[#292238]">
    <section className="w-full max-w-xl rounded-3xl border border-purple-100 bg-white p-9 shadow-sm">
      <p className="font-semibold text-[#7654c7]">✦ MY CLASSROOM</p><h1 className="mt-5 text-4xl font-bold">Your learning space.<br />Your private account.</h1>
      <p className="my-6 text-[#777080]">Sign in to save your study progress and review account-security alerts.</p>
      {error && <p role="alert" className="mb-4 text-red-700">{error}</p>}
      <div className="flex flex-wrap gap-4"><a className="rounded-xl bg-[#7654c7] px-6 py-3 font-semibold text-white" href="/login">Sign in</a><a className="rounded-xl border border-purple-200 px-6 py-3 font-semibold" href="/register">Create account</a></div>
      <p className="mt-8 text-sm text-[#777080]">Research prototype · Advisory alerts, no automatic blocking</p>
    </section></main>;

  const securityPanel = <section aria-label="Account security" className="mb-8 rounded-2xl border border-[#eee8fa] bg-white p-5">
    <div className="flex flex-wrap items-center justify-between gap-4"><div><h3 className="font-bold">Account & security</h3><p className="break-all text-sm text-[#777080]">{state.user.email} · {state.user.verified ? 'Email verified' : 'Email verification pending'}</p></div>
      <div className="flex flex-wrap items-center gap-4 text-sm font-semibold text-[#7654c7]"><a href="/account">My alerts ({state.security.alerts.length})</a>{state.user.role === 'admin' && <a href="/admin">Security operations</a>}
        <form method="post" action="/logout"><input type="hidden" name="csrf" value={state.csrf} /><button type="submit">Sign out</button></form></div></div>
    <p className="mt-3 text-xs text-[#777080]">{state.security.email_mode === 'smtp' ? 'SMTP delivery is configured; check notification records for delivery status.' : state.security.email_mode === 'outbox' ? 'Notifications are saved in the local demo outbox—not sent to your inbox.' : 'Email delivery is not enabled. Notifications remain queued.'} Login monitoring uses rules. Network ML is a separate signal.</p>
    {state.security.alerts.length > 0 && <div className="mt-4 rounded-xl bg-amber-50 p-4"><strong>{state.security.alerts[0].title}</strong><p className="mt-1 text-sm">{state.security.alerts[0].explanation.failed_attempts} failed attempts in {state.security.alerts[0].explanation.window_seconds} seconds. This is suspicious activity, not proof of account access. <a className="underline" href="/account">Review</a></p></div>}
    <p aria-live="polite" className="mt-2 text-xs">{saving ? 'Saving progress…' : 'Progress is stored privately in your account.'}</p>
    {error && <p role="alert" className="mt-3 text-red-700">{error}</p>}
  </section>;
  return children({ completed: state.completed, tasks: state.tasks, saving, securityPanel,
    onComplete: (id, total) => save({ ...state.completed, [id]: Math.min(state.completed[id] + 1, total) }, state.tasks),
    onTask: id => save(state.completed, { ...state.tasks, [id]: !state.tasks[id] }) });
}
