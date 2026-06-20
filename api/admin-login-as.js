const { send, requireAdmin } = require('./_auth');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  try {
    await requireAdmin(req);
    send(res, 501, {
      error: 'Cognito does not support secure admin impersonation/magic login links by default. Use a custom audited impersonation service or remove this admin action.'
    });
  } catch (err) {
    send(res, /Admin access|required|authorization|token/i.test(err.message || '') ? 401 : 500, { error: err.message || 'Admin access required' });
  }
};
