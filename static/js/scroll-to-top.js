document.addEventListener('DOMContentLoaded', function() {
    const scrollBtn = document.getElementById('scrollTopBtn');
    const scrollContainer = document.querySelector('.scroll-to-top');

    if (scrollBtn && scrollContainer) {
        // Show/hide button based on scroll position
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                scrollContainer.classList.add('show');
            } else {
                scrollContainer.classList.remove('show');
            }
        });

        // Smooth scroll to top when clicked
        scrollBtn.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
});