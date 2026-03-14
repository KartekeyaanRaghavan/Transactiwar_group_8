/**
 * TransactiWar - Client-side JavaScript
 *
 * SECURITY NOTE: Client-side validation is for UX only.
 * All validation MUST be duplicated on the server side.
 * Never trust client-side validation for security.
 */

document.addEventListener('DOMContentLoaded', function () {

    // --- Mobile Navigation Toggle ---
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.querySelector('.nav-links');
    if (navToggle && navLinks) {
        navToggle.addEventListener('click', function () {
            navLinks.classList.toggle('active');
        });
    }

    // --- Auto-dismiss alerts after 5 seconds ---
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.5s ease';
            alert.style.opacity = '0';
            setTimeout(function () {
                alert.remove();
            }, 500);
        }, 5000);
    });

    // --- Password strength indicator ---
    const passwordInput = document.getElementById('password');
    const strengthIndicator = document.getElementById('passwordStrength');
    if (passwordInput && strengthIndicator) {
        passwordInput.addEventListener('input', function () {
            const password = this.value;
            let strength = 0;
            let feedback = [];

            if (password.length >= 8) strength++;
            else feedback.push('At least 8 characters');

            if (/[A-Z]/.test(password)) strength++;
            else feedback.push('An uppercase letter');

            if (/[a-z]/.test(password)) strength++;
            else feedback.push('A lowercase letter');

            if (/[0-9]/.test(password)) strength++;
            else feedback.push('A digit');

            if (/[^a-zA-Z0-9]/.test(password)) strength++;
            else feedback.push('A special character');

            const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
            const colors = ['#d93025', '#ea4335', '#f9ab00', '#0f9d58', '#0f9d58'];

            if (password.length === 0) {
                strengthIndicator.textContent = '';
                strengthIndicator.style.color = '';
            } else {
                strengthIndicator.textContent = labels[strength - 1] || 'Very Weak';
                strengthIndicator.style.color = colors[strength - 1] || '#d93025';
                if (feedback.length > 0) {
                    strengthIndicator.textContent += ' — Need: ' + feedback.join(', ');
                }
            }
        });
    }

    // --- Confirm money transfer ---
    const transferForm = document.getElementById('transferForm');
    if (transferForm) {
        transferForm.addEventListener('submit', function (e) {
            const amount = document.getElementById('amount');
            const receiverId = document.getElementById('receiver_id');

            if (amount && receiverId) {
                var amountVal = parseFloat(amount.value);
                var receiverVal = receiverId.value.trim();

                if (isNaN(amountVal) || amountVal <= 0) {
                    e.preventDefault();
                    showFormError('amount', 'Please enter a valid amount greater than zero.');
                    return;
                }

                if (!receiverVal || isNaN(parseInt(receiverVal))) {
                    e.preventDefault();
                    showFormError('receiver_id', 'Please enter a valid user ID.');
                    return;
                }

                // SECURITY NOTE: Confirm dialog can be bypassed by attackers.
                // Server-side validation is the actual security measure.
                if (!confirm('Are you sure you want to transfer Rs. ' + amountVal.toFixed(2) + ' to user #' + receiverVal + '?')) {
                    e.preventDefault();
                }
            }
        });
    }

    // --- Form input sanitization (UX, not security) ---
    // Trim whitespace from text inputs on blur
    var textInputs = document.querySelectorAll('input[type="text"], input[type="email"]');
    textInputs.forEach(function (input) {
        input.addEventListener('blur', function () {
            this.value = this.value.trim();
        });
    });
});

/**
 * Show a form error message next to an input.
 *
 * @param {string} inputId
 * @param {string} message
 */
function showFormError(inputId, message) {
    var input = document.getElementById(inputId);
    if (!input) return;

    // Remove existing error
    var existingError = input.parentElement.querySelector('.form-error');
    if (existingError) existingError.remove();

    var errorDiv = document.createElement('div');
    errorDiv.className = 'form-error';
    // SECURITY: Use textContent to set error message (not innerHTML) to prevent DOM XSS
    errorDiv.textContent = message;
    input.parentElement.appendChild(errorDiv);
}
