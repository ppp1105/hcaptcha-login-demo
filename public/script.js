let hcaptchaWidgetId = null;

// Explicit render (render=explicit in the script URL) instead of the
// default auto-render: the sitekey only exists after we fetch it from our
// own backend, so auto-render (which scans the DOM as soon as api.js
// loads) would race against that fetch and could render the widget with
// an empty/stale sitekey. Rendering it ourselves, once, avoids that.
window.onHcaptchaApiLoad = async function onHcaptchaApiLoad() {
  // The sitekey is public by nature: it can come from the backend with no
  // security risk.
  const { sitekey } = await fetch('/api/config').then((r) => r.json());
  // Force English regardless of the browser/OS locale - the widget
  // otherwise follows the visitor's Accept-Language.
  hcaptchaWidgetId = window.hcaptcha.render('captcha', { sitekey, hl: 'en' });
};

function init() {
  const form = document.getElementById('login-form');
  const feedback = document.getElementById('feedback');
  const submitBtn = document.getElementById('submit-btn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    feedback.textContent = '';
    submitBtn.disabled = true;

    const email = form.email.value.trim();
    const password = form.password.value;
    const captchaToken = hcaptchaWidgetId !== null ? window.hcaptcha.getResponse(hcaptchaWidgetId) : '';

    if (!captchaToken) {
      feedback.textContent = 'Please solve the captcha before continuing.';
      feedback.className = 'error';
      submitBtn.disabled = false;
      return;
    }

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, captchaToken }),
      });
      const data = await res.json();

      if (res.ok) {
        feedback.textContent = data.message;
        feedback.className = 'success';
      } else {
        feedback.textContent = errorMessage(data.error);
        feedback.className = 'error';
      }
    } catch (err) {
      feedback.textContent = 'Network error. Please try again.';
      feedback.className = 'error';
    } finally {
      // An hCaptcha token can only be used once - always reset after an attempt.
      if (hcaptchaWidgetId !== null) window.hcaptcha.reset(hcaptchaWidgetId);
      submitBtn.disabled = false;
    }
  });
}

function errorMessage(code) {
  // Deliberately generic messages: they do not reveal which specific field is wrong.
  const map = {
    invalid_request: 'Please enter a valid email and password.',
    invalid_credentials: 'Invalid email or password.',
    captcha_required: 'Please solve the captcha before continuing.',
    captcha_failed: 'Could not verify the captcha. Please try again.',
    too_many_attempts: 'Too many attempts. Please wait a moment before trying again.',
    captcha_verification_unavailable: 'Verification service unavailable. Please try again shortly.',
  };
  return map[code] || 'Something went wrong. Please try again.';
}

init();
