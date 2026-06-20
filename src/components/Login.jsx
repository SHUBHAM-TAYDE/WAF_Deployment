import { useState } from 'react';
import { motion } from 'framer-motion';
import { Lock, Activity, Eye, EyeOff, Server, ShieldCheck, LayoutDashboard, TerminalSquare } from 'lucide-react';

const Login = ({ setAuth }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`http://${window.location.host}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          username: username,
          password: password,
        }),
      });

      if (!response.ok) {
        throw new Error('Invalid credentials');
      }

      const data = await response.json();
      localStorage.setItem('waf_token', data.access_token);
      setAuth(true);
    } catch (err) {
      setError(err.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      {/* Left Panel: Showcase */}
      <div className="login-showcase">
        <div className="showcase-content">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="login-brand" style={{ marginBottom: '32px' }}>
              <img src="/Cybersentinel.png" alt="CyberSentinel" style={{ maxWidth: '100%', height: 'auto', maxHeight: '120px', objectFit: 'contain' }} className="brand-icon-large" />
            </div>
            <p className="brand-subtitle">Enterprise Web Application Firewall & Threat Monitoring Platform</p>
            <p className="brand-description">
              A modern WAF platform providing real-time protection against SQL Injection, XSS, RCE, protocol violations, bots, and OWASP Top 10 attacks using ModSecurity and OWASP CRS.
            </p>
          </motion.div>

          <div className="feature-grid">
            <motion.div className="feature-card" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }}>
              <Activity size={24} className="feature-icon blue" />
              <div>
                <h3>Real-Time Monitoring</h3>
                <p>Live attack detection and tracking</p>
              </div>
            </motion.div>
            <motion.div className="feature-card" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}>
              <LayoutDashboard size={24} className="feature-icon orange" />
              <div>
                <h3>Security Analytics</h3>
                <p>Advanced dashboard and metrics</p>
              </div>
            </motion.div>
            <motion.div className="feature-card" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}>
              <ShieldCheck size={24} className="feature-icon green" />
              <div>
                <h3>OWASP CRS Integrations</h3>
                <p>Industry-standard core rule set</p>
              </div>
            </motion.div>
            <motion.div className="feature-card" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 }}>
              <TerminalSquare size={24} className="feature-icon purple" />
              <div>
                <h3>Live WAF Logs</h3>
                <p>Deep packet and log inspection</p>
              </div>
            </motion.div>
          </div>

          <motion.div className="system-status-panel" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
            <div className="status-item">
              <span className="pulse-dot green"></span> WAF Active
            </div>
            <div className="status-item">
              <span className="pulse-dot green"></span> ModSecurity Running
            </div>
            <div className="status-item">
              <span className="pulse-dot blue"></span> OWASP CRS Loaded
            </div>
          </motion.div>
        </div>

        {/* Animated Background Elements */}
        <div className="cyber-grid"></div>
        <div className="glow-sphere sphere-1"></div>
        <div className="glow-sphere sphere-2"></div>
      </div>

      {/* Right Panel: Login Form */}
      <div className="login-form-wrapper">
        <motion.div
          className="login-card glass-panel"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4, delay: 0.2 }}
        >
          <div className="login-card-header">
            <Lock size={28} className="auth-icon" />
            <h2>Secure Access</h2>
            <p>Authenticate to access the SOC dashboard</p>
          </div>

          {error && (
            <motion.div className="login-error" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}>
              {error}
            </motion.div>
          )}

          <form onSubmit={handleLogin} className="login-form">
            <div className="form-group">
              <label htmlFor="username">Admin Identity</label>
              <div className="input-with-icon">
                <Server size={18} className="input-icon" />
                <input
                  id="username"
                  type="text"
                  placeholder="Enter username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="password">Authentication Key</label>
              <div className="input-with-icon">
                <Lock size={18} className="input-icon" />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className={`login-btn ${loading ? 'loading' : ''}`}
              disabled={loading}
            >
              {loading ? (
                <>
                  <Activity className="animate-spin" size={18} /> Authenticating...
                </>
              ) : (
                'Initialize Session'
              )}
            </button>
          </form>

          <div className="login-footer">
            <p>Unauthorized access is strictly prohibited and monitored.</p>
            <p>Demo Credentials: admin / admin123</p>
          </div>
        </motion.div>
      </div>

      <div className="login-footer-bar">
        <div className="footer-left">
          <img src="/logo.png" alt="Virtual Galaxy" className="footer-logo" />
          <div className="footer-divider"></div>
          <span>Information Technology Services Management</span>
        </div>

        <div className="footer-center">
          <span>&copy; 2026 Virtual Galaxy Ltd. All Rights Reserved.</span>
        </div>

        <div className="footer-right">
          <span>Version 1.0</span>
          <div className="footer-divider"></div>
          <a href="#support">Support</a>
          <div className="footer-divider"></div>
          <a href="#privacy">Privacy Policy</a>
        </div>
      </div>

    </div>
  );
};

export default Login;
