document.addEventListener('DOMContentLoaded', function() {
    // Copy text functionality
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const resultText = this.closest('.result-box').querySelector('.result-text');
            
            if (resultText) {
                // Create a temporary textarea element to copy from
                const textarea = document.createElement('textarea');
                textarea.value = resultText.textContent;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                
                // Change the button text temporarily
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                
                setTimeout(() => {
                    this.textContent = originalText;
                }, 2000);
            }
        });
    });
    
    // Auto-select active nav link
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-links a');
    
    navLinks.forEach(function(link) {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
    
    // Automatically dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    
    alerts.forEach(function(alert) {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => {
                alert.remove();
            }, 300);
        }, 5000);
    });
});